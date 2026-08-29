//! Atomic PostgreSQL persistence for OAuth and OpenID Connect protocol state.

use std::fmt;

use omnius_auth_core::{AssuranceLevel, AuthMethod, Scope, SubjectId, TenantId};
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use serde_json::Value;
use sqlx::{Connection as _, Postgres, Row as _, Transaction, postgres::PgRow};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::{Uuid, Variant, Version};

use crate::{
    crypto::BearerDigest,
    types::{
        ApplicationType, ClientId, GrantId, GrantType, IssuerUri, JwtId, PkceChallenge,
        PkceVerifier, Prompt, RedirectUri, ResourceUri, ResponseMode, ResponseType,
        TokenEndpointAuthMethod,
    },
};

const MAX_LIST_LIMIT: u16 = 100;
const MAX_ASSERTION_JTI_BYTES: usize = 255;
const MAX_DISPLAY_NAME_BYTES: usize = 255;
const MAX_CLIENT_URI_BYTES: usize = 2_048;
const MAX_STATE_BYTES: usize = 2_048;
const MAX_NONCE_BYTES: usize = 255;
const MAX_RESOURCE_NAME_BYTES: usize = 128;
const MAX_RESOURCE_DESCRIPTION_BYTES: usize = 1_024;
const MAX_SCOPE_DESCRIPTION_BYTES: usize = 512;
const PUBLIC_SUBJECT_BYTES: usize = 43;
const MAX_AUTH_METHODS: usize = 16;
const MAX_RESOURCES: usize = 16;
const MAX_SCOPES: usize = 128;

macro_rules! uuid_v7_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new UUIDv7 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores an identifier after validating UUID version and variant.
            pub fn from_uuid(value: Uuid) -> Result<Self, OAuthStoreError> {
                valid_uuid_v7(value)?;
                Ok(Self(value))
            }

            /// Returns the database UUID.
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
    };
}

uuid_v7_id!(
    OAuthClientRecordId,
    "Internal durable OAuth client row identifier."
);
uuid_v7_id!(
    AuthorizationRequestId,
    "Durable authorization request identifier."
);
uuid_v7_id!(
    OAuthSubjectId,
    "Issuer-local durable subject row identifier."
);
uuid_v7_id!(RefreshFamilyId, "Refresh-token family identifier.");
uuid_v7_id!(RefreshTokenId, "Refresh-token row identifier.");

/// Stable random public subject identifier exposed by this issuer.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicSubject(String);

impl PublicSubject {
    /// Validates a canonical 32-byte unpadded base64url subject value.
    pub fn parse(value: impl Into<String>) -> Result<Self, OAuthStoreError> {
        let value = value.into();
        if value.len() != PUBLIC_SUBJECT_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OAuthStoreError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the exact public subject.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PublicSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicSubject([REDACTED])")
    }
}

/// Origin of one registered OAuth client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientSource {
    /// Administrator-managed registration.
    PreRegistered,
    /// HTTPS Client ID Metadata Document.
    ClientIdMetadata,
    /// Optional dynamic client registration.
    Dynamic,
}

impl ClientSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PreRegistered => "pre_registered",
            Self::ClientIdMetadata => "client_id_metadata",
            Self::Dynamic => "dynamic",
        }
    }

    fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "pre_registered" => Ok(Self::PreRegistered),
            "client_id_metadata" => Ok(Self::ClientIdMetadata),
            "dynamic" => Ok(Self::Dynamic),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// Current client lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientStatus {
    /// The client may initiate and use grants.
    Active,
    /// The client and all its grants are disabled.
    Disabled,
}

impl ClientStatus {
    fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// Cached, already-validated Client ID Metadata Document state.
#[derive(Clone, Debug)]
pub struct ClientMetadataCache {
    /// Strict validated JSON object.
    pub body: Value,
    /// HTTP entity tag retained for conditional revalidation.
    pub etag: Option<String>,
    /// HTTP Last-Modified value retained for conditional revalidation.
    pub last_modified: Option<String>,
    /// Time the response became the accepted cache entry.
    pub cached_at: OffsetDateTime,
    /// Hard cache expiry.
    pub expires_at: OffsetDateTime,
}

/// Complete validated client state accepted by the persistence boundary.
pub struct ClientUpsert {
    /// Stable protocol client identifier.
    pub client_id: ClientId,
    /// Registration source.
    pub source: ClientSource,
    /// Safe human-readable display name.
    pub display_name: String,
    /// Optional client home page.
    pub client_uri: Option<String>,
    /// Optional logo URL.
    pub logo_uri: Option<String>,
    /// Web or native application class.
    pub application_type: ApplicationType,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Exact HMAC digest for a confidential client secret.
    pub client_secret_digest: Option<BearerDigest>,
    /// Supported response types.
    pub response_types: Vec<ResponseType>,
    /// Supported grant types.
    pub grant_types: Vec<GrantType>,
    /// Optional client-declared scope allow-list; empty means provider policy decides.
    pub allowed_scopes: Vec<Scope>,
    /// Public assertion keys.
    pub public_jwks: Option<Value>,
    /// Exact registered authorization redirects.
    pub redirect_uris: Vec<RedirectUri>,
    /// Exact registered post-logout redirects.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// CIMD document URL; necessarily identical to a CIMD client ID.
    pub metadata_document_uri: Option<String>,
    /// Optional validated metadata cache.
    pub metadata_cache: Option<ClientMetadataCache>,
    /// Mutation timestamp.
    pub now: OffsetDateTime,
}

impl fmt::Debug for ClientUpsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientUpsert")
            .field("client_id", &self.client_id)
            .field("source", &self.source)
            .field("display_name", &self.display_name)
            .field("application_type", &self.application_type)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("client_secret_digest", &"[REDACTED]")
            .field("redirect_uri_count", &self.redirect_uris.len())
            .field(
                "post_logout_redirect_uri_count",
                &self.post_logout_redirect_uris.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Safe registered-client metadata. Secret digests and cache bodies are excluded.
#[derive(Clone, Debug)]
pub struct RegisteredClient {
    /// Internal durable row identifier.
    pub id: OAuthClientRecordId,
    /// Protocol client identifier.
    pub client_id: ClientId,
    /// Registration source.
    pub source: ClientSource,
    /// Lifecycle state.
    pub status: ClientStatus,
    /// Safe display name.
    pub display_name: String,
    /// Optional client home page.
    pub client_uri: Option<String>,
    /// Optional logo URL.
    pub logo_uri: Option<String>,
    /// Application class.
    pub application_type: ApplicationType,
    /// Client authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Supported response types.
    pub response_types: Vec<ResponseType>,
    /// Supported grant types.
    pub grant_types: Vec<GrantType>,
    /// Optional client-declared scope allow-list; empty means provider policy decides.
    pub allowed_scopes: Vec<Scope>,
    /// Public assertion keys.
    pub public_jwks: Option<Value>,
    /// Exact authorization redirects.
    pub redirect_uris: Vec<RedirectUri>,
    /// Exact post-logout redirects.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// CIMD cache expiry used to force metadata revalidation.
    pub metadata_cache_expires_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last mutation time.
    pub updated_at: OffsetDateTime,
    /// Disable time.
    pub disabled_at: Option<OffsetDateTime>,
}

/// Authentication material loaded separately from safe client metadata.
#[derive(Clone)]
pub struct ClientAuthentication {
    /// Internal client row identifier.
    pub id: OAuthClientRecordId,
    /// Protocol client identifier.
    pub client_id: ClientId,
    /// Authentication method.
    pub method: TokenEndpointAuthMethod,
    /// Exact stored client-secret digest, when applicable.
    pub client_secret_digest: Option<BearerDigest>,
    /// Public keys for private-key JWT, when applicable.
    pub public_jwks: Option<Value>,
}

impl fmt::Debug for ClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientAuthentication")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("method", &self.method)
            .field("client_secret_digest", &"[REDACTED]")
            .field("has_public_jwks", &self.public_jwks.is_some())
            .finish()
    }
}

/// Atomic disable result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientDisableOutcome {
    /// Whether this call changed the client from active to disabled.
    pub newly_disabled: bool,
    /// Grants newly revoked by this call.
    pub grants_revoked: u64,
    /// Refresh families newly revoked by this call.
    pub refresh_families_revoked: u64,
}

/// Result of recording a private-key JWT assertion replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAssertionRecord {
    /// This `(client, jti)` was accepted and persisted.
    Accepted,
    /// The assertion was already recorded.
    Replay,
    /// The client is missing or disabled.
    ClientUnavailable,
}

/// Durable browser interaction state retained without protocol secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationInteractionRequirement {
    /// Authentication or fresh reauthentication is required.
    Login,
    /// Explicit consent is required.
    Consent,
    /// The existing grant covers the request.
    Ready,
}

impl AuthorizationInteractionRequirement {
    const fn as_db(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Consent => "consent",
            Self::Ready => "ready",
        }
    }

    fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "login" => Ok(Self::Login),
            "consent" => Ok(Self::Consent),
            "ready" => Ok(Self::Ready),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// One safe scope display row retained in canonical requested-scope order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationInteractionScope {
    /// Exact requested scope.
    pub name: Scope,
    /// Safe provider-authored description.
    pub description: String,
    /// Whether the scope extends beyond an existing grant.
    pub newly_requested: bool,
}

/// Durable pending authorization request input.
pub struct AuthorizationRequestCreate {
    /// Exact digest of the browser handle.
    pub handle_digest: BearerDigest,
    /// Validated client identifier.
    pub client_id: ClientId,
    /// Exact registered redirect URI.
    pub redirect_uri: RedirectUri,
    /// Response type.
    pub response_type: ResponseType,
    /// Response mode.
    pub response_mode: ResponseMode,
    /// Opaque client state.
    pub client_state: Option<String>,
    /// Requested scopes.
    pub requested_scopes: Vec<Scope>,
    /// Requested resources.
    pub resource_uris: Vec<ResourceUri>,
    /// S256 PKCE challenge.
    pub pkce_code_challenge: PkceChallenge,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// Prompt values.
    pub prompt_values: Vec<Prompt>,
    /// Maximum authentication age.
    pub max_age_seconds: Option<u64>,
    /// Exact expected issuer.
    pub expected_issuer: IssuerUri,
    /// Safe configured resource display name.
    pub interaction_resource_name: String,
    /// Safe configured resource display description.
    pub interaction_resource_description: String,
    /// Configured minimum resource assurance.
    pub interaction_minimum_assurance: AssuranceLevel,
    /// Safe scope descriptions and existing-grant delta.
    pub interaction_scopes: Vec<AuthorizationInteractionScope>,
    /// Exact browser interaction requirement.
    pub interaction_requirement: AuthorizationInteractionRequirement,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for AuthorizationRequestCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestCreate")
            .field("handle_digest", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &"[REDACTED]")
            .field("scope_count", &self.requested_scopes.len())
            .field("resource_count", &self.resource_uris.len())
            .finish_non_exhaustive()
    }
}

/// Authorization request lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationRequestStatus {
    /// Awaiting user interaction.
    Pending,
    /// User approved the request.
    Approved,
    /// User denied the request.
    Denied,
    /// Request expired before a decision.
    Expired,
}

impl AuthorizationRequestStatus {
    fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// Loaded authorization request. Its bearer digest is deliberately excluded.
#[derive(Clone)]
pub struct AuthorizationRequestRecord {
    /// Durable request identifier.
    pub id: AuthorizationRequestId,
    /// Safe client metadata.
    pub client: RegisteredClient,
    /// Exact validated redirect.
    pub redirect_uri: RedirectUri,
    /// Response type.
    pub response_type: ResponseType,
    /// Response mode.
    pub response_mode: ResponseMode,
    /// Opaque client state required only at the redirect boundary.
    pub client_state: Option<String>,
    /// Requested scopes.
    pub requested_scopes: Vec<Scope>,
    /// Requested resources.
    pub resource_uris: Vec<ResourceUri>,
    /// S256 challenge.
    pub pkce_code_challenge: PkceChallenge,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// Prompt values.
    pub prompt_values: Vec<Prompt>,
    /// Maximum authentication age.
    pub max_age_seconds: Option<u64>,
    /// Expected issuer.
    pub expected_issuer: IssuerUri,
    /// Safe configured resource display name.
    pub interaction_resource_name: String,
    /// Safe configured resource display description.
    pub interaction_resource_description: String,
    /// Configured minimum resource assurance.
    pub interaction_minimum_assurance: AssuranceLevel,
    /// Safe scope descriptions and existing-grant delta.
    pub interaction_scopes: Vec<AuthorizationInteractionScope>,
    /// Exact browser interaction requirement.
    pub interaction_requirement: AuthorizationInteractionRequirement,
    /// Lifecycle state.
    pub status: AuthorizationRequestStatus,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Terminal transition time.
    pub completed_at: Option<OffsetDateTime>,
}

impl fmt::Debug for AuthorizationRequestRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestRecord")
            .field("id", &self.id)
            .field("client_id", &self.client.client_id)
            .field("status", &self.status)
            .field("scope_count", &self.requested_scopes.len())
            .field("resource_count", &self.resource_uris.len())
            .finish_non_exhaustive()
    }
}

/// Result of loading a recognized authorization request handle.
#[derive(Clone, Debug)]
pub enum AuthorizationRequestLoad {
    /// Pending, live request.
    Pending(AuthorizationRequestRecord),
    /// Recognized request that was atomically marked expired.
    Expired,
    /// Unknown, terminal, or client-disabled request.
    Unavailable,
}

/// Terminal browser decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Consent approved.
    Approve,
    /// Consent denied.
    Deny,
}

impl AuthorizationDecision {
    const fn status(self) -> &'static str {
        match self {
            Self::Approve => "approved",
            Self::Deny => "denied",
        }
    }
}

/// Result of a terminal authorization-request transition.
#[derive(Clone, Debug)]
pub enum AuthorizationTransition {
    /// The request moved to its requested terminal state.
    Completed(AuthorizationRequestRecord),
    /// The request expired and was atomically marked expired.
    Expired,
    /// The request is unknown, already terminal, or belongs to a disabled client.
    Unavailable,
}

/// Stable issuer subject allocation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthSubject {
    /// Internal subject row identifier.
    pub id: OAuthSubjectId,
    /// Internal user identifier.
    pub user_id: SubjectId,
    /// Stable issuer public subject.
    pub public_subject: PublicSubject,
    /// Allocation time.
    pub created_at: OffsetDateTime,
}

/// Input for a durable consent grant.
#[derive(Clone, Debug)]
pub struct GrantCreate {
    /// Active user receiving the grant.
    pub user_id: SubjectId,
    /// Optional active tenant membership binding.
    pub tenant_id: Option<TenantId>,
    /// Active client receiving consent.
    pub client_id: ClientId,
    /// Exact resource set.
    pub resources: Vec<ResourceUri>,
    /// Exact granted scope set.
    pub granted_scopes: Vec<Scope>,
    /// Time of user authentication.
    pub authenticated_at: OffsetDateTime,
    /// Authentication assurance.
    pub assurance_level: AssuranceLevel,
    /// Authentication methods.
    pub authentication_methods: Vec<AuthMethod>,
    /// Explicit consent time.
    pub consented_at: OffsetDateTime,
}

/// Live grant state used by token issuance and verification.
#[derive(Clone, Debug)]
pub struct LiveGrant {
    /// Grant identifier.
    pub id: GrantId,
    /// Issuer-local public subject.
    pub public_subject: PublicSubject,
    /// Internal user identifier, retained only inside the issuer.
    pub user_id: SubjectId,
    /// Optional tenant binding.
    pub tenant_id: Option<TenantId>,
    /// Client identifier.
    pub client_id: ClientId,
    /// Resource set.
    pub resources: Vec<ResourceUri>,
    /// Granted scopes.
    pub granted_scopes: Vec<Scope>,
    /// Authentication time.
    pub authenticated_at: OffsetDateTime,
    /// Authentication assurance.
    pub assurance_level: AssuranceLevel,
    /// Authentication methods.
    pub authentication_methods: Vec<AuthMethod>,
    /// Consent time.
    pub consented_at: OffsetDateTime,
    /// Grant version.
    pub version: i64,
}

/// Pagination cursor for connected grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantCursor {
    /// Creation timestamp of the preceding row.
    pub created_at: OffsetDateTime,
    /// Grant identifier of the preceding row.
    pub id: GrantId,
}

/// Safe connected-application metadata.
#[derive(Clone, Debug)]
pub struct ConnectedGrant {
    /// Grant identifier exposed for owner revocation.
    pub grant_id: GrantId,
    /// Protocol client identifier.
    pub client_id: ClientId,
    /// Safe display name.
    pub client_name: String,
    /// Optional client home page.
    pub client_uri: Option<String>,
    /// Optional logo URL.
    pub logo_uri: Option<String>,
    /// Optional tenant binding.
    pub tenant_id: Option<TenantId>,
    /// Resource set.
    pub resources: Vec<ResourceUri>,
    /// Granted scopes.
    pub granted_scopes: Vec<Scope>,
    /// Consent time.
    pub consented_at: OffsetDateTime,
    /// Creation time used by pagination.
    pub created_at: OffsetDateTime,
}

/// Bounded connected-grant page.
#[derive(Clone, Debug)]
pub struct ConnectedGrantPage {
    /// Safe grant rows.
    pub grants: Vec<ConnectedGrant>,
    /// Cursor for the next page.
    pub next: Option<GrantCursor>,
}

/// Authorization code persistence input.
#[derive(Clone)]
pub struct AuthorizationCodeCreate {
    /// Exact code digest.
    pub code_digest: BearerDigest,
    /// Live grant receiving the code.
    pub grant_id: GrantId,
    /// Bound client.
    pub client_id: ClientId,
    /// Bound exact redirect.
    pub redirect_uri: RedirectUri,
    /// Bound resources.
    pub resource_uris: Vec<ResourceUri>,
    /// Bound scopes.
    pub granted_scopes: Vec<Scope>,
    /// Bound S256 challenge.
    pub pkce_code_challenge: PkceChallenge,
    /// Bound OIDC nonce.
    pub nonce: Option<String>,
    /// Issuance time.
    pub issued_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for AuthorizationCodeCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeCreate")
            .field("code_digest", &"[REDACTED]")
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Exact token-endpoint bindings supplied with a code.
pub struct AuthorizationCodeBinding {
    /// Authenticated client.
    pub client_id: ClientId,
    /// Exact redirect URI.
    pub redirect_uri: RedirectUri,
    /// Exact resource set.
    pub resource_uris: Vec<ResourceUri>,
    /// PKCE verifier whose S256 result must match.
    pub pkce_verifier: PkceVerifier,
}

impl fmt::Debug for AuthorizationCodeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeBinding")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &"[REDACTED]")
            .field("resource_count", &self.resource_uris.len())
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

/// Successfully consumed code state used for token issuance.
#[derive(Clone, Debug)]
pub struct ConsumedAuthorizationCode {
    /// Live grant.
    pub grant: LiveGrant,
    /// Bound redirect.
    pub redirect_uri: RedirectUri,
    /// Bound resources.
    pub resource_uris: Vec<ResourceUri>,
    /// Bound scopes.
    pub granted_scopes: Vec<Scope>,
    /// OIDC nonce.
    pub nonce: Option<String>,
}

/// Rejection classification after consuming a recognized code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationCodeRejection {
    /// The recognized code expired.
    Expired,
    /// A client, redirect, resource, or PKCE binding failed.
    BindingMismatch,
    /// Stored code resources or scopes exceed its grant, proving durable corruption.
    StoredBindingViolation,
    /// User, client, grant, or tenant membership is no longer active.
    Inactive,
}

/// Atomic code-exchange result.
#[derive(Clone, Debug)]
pub enum AuthorizationCodeExchange {
    /// Code consumed and its live grant returned.
    Issued(ConsumedAuthorizationCode),
    /// Recognized code consumed with a rejected outcome.
    Rejected(AuthorizationCodeRejection),
    /// Digest is unknown or was already consumed.
    Unavailable,
}

/// Initial refresh family and token input.
pub struct RefreshFamilyIssue {
    /// Live grant.
    pub grant_id: GrantId,
    /// Bound client.
    pub client_id: ClientId,
    /// Exact resource bound at authorization-code exchange.
    pub resource: ResourceUri,
    /// Exact scope subset bound at authorization-code exchange.
    pub granted_scopes: Vec<Scope>,
    /// First refresh-token digest.
    pub token_digest: BearerDigest,
    /// Family creation time.
    pub issued_at: OffsetDateTime,
    /// Family and token expiry.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for RefreshFamilyIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshFamilyIssue")
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .field("token_digest", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Persisted refresh-token coordinates returned without bearer material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuedRefreshToken {
    /// Family identifier.
    pub family_id: RefreshFamilyId,
    /// Token row identifier.
    pub token_id: RefreshTokenId,
    /// Rotation sequence, beginning at zero.
    pub rotation_sequence: i64,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

/// Successful refresh rotation state.
#[derive(Clone, Debug)]
pub struct RotatedRefreshToken {
    /// Live grant for token issuance.
    pub grant: LiveGrant,
    /// Exact resource inherited from the refresh family.
    pub resource: ResourceUri,
    /// Maximum scopes inherited from the refresh family.
    pub granted_scopes: Vec<Scope>,
    /// Family identifier.
    pub family_id: RefreshFamilyId,
    /// Replacement token identifier.
    pub token_id: RefreshTokenId,
    /// Replacement rotation sequence.
    pub rotation_sequence: i64,
    /// Replacement expiry.
    pub expires_at: OffsetDateTime,
}

/// Refresh rejection without a reuse signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshRejection {
    /// Digest is not recognized.
    Unknown,
    /// Token or family expired.
    Expired,
    /// Client binding failed.
    ClientMismatch,
    /// User, client, grant, or tenant is inactive.
    Inactive,
}

/// Atomic refresh rotation result.
#[derive(Clone, Debug)]
pub enum RefreshRotation {
    /// Successful mandatory rotation.
    Rotated(RotatedRefreshToken),
    /// Any consumed or revoked family member was reused; family and grant are revoked.
    ReuseDetected {
        /// Compromised family.
        family_id: RefreshFamilyId,
        /// Revoked grant.
        grant_id: GrantId,
    },
    /// Request rejected without changing the token.
    Rejected(RefreshRejection),
}

/// Access-token revocation reason represented by the schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRevocationReason {
    /// Client was disabled.
    ClientDisabled,
    /// Grant was revoked.
    GrantRevoked,
    /// Logout invalidated the access token.
    Logout,
    /// Administrator or owner manually revoked it.
    Manual,
    /// RFC 7009 token revocation.
    TokenRevoked,
    /// User was disabled.
    UserDisabled,
}

impl AccessRevocationReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientDisabled => "client_disabled",
            Self::GrantRevoked => "grant_revoked",
            Self::Logout => "logout",
            Self::Manual => "manual",
            Self::TokenRevoked => "token_revoked",
            Self::UserDisabled => "user_disabled",
        }
    }
}

/// Persisted access-token revocation input.
#[derive(Clone, Debug)]
pub struct AccessTokenRevocation {
    /// Access token `jti`.
    pub jti: JwtId,
    /// Bound grant.
    pub grant_id: GrantId,
    /// Bound client.
    pub client_id: ClientId,
    /// Access token issuance time.
    pub issued_at: OffsetDateTime,
    /// Access token expiry.
    pub expires_at: OffsetDateTime,
    /// Revocation time.
    pub revoked_at: OffsetDateTime,
    /// Revocation reason.
    pub reason: AccessRevocationReason,
}

/// Untrusted token claims reduced to the fields required for a live-state check.
#[derive(Clone, Debug)]
pub struct AccessTokenLiveCheck {
    /// Access token `jti`.
    pub jti: JwtId,
    /// Grant claim.
    pub grant_id: GrantId,
    /// Public subject claim.
    pub public_subject: PublicSubject,
    /// Client claim.
    pub client_id: ClientId,
    /// Legacy caller-supplied tenant hint. Live checks resolve membership from the grant itself.
    pub tenant_id: Option<TenantId>,
    /// Resource audience being used.
    pub resource: ResourceUri,
    /// Token scopes, which must remain a subset of the grant.
    pub scopes: Vec<Scope>,
}

/// Verified local email value. Debug output never reveals it.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedEmail(String);

impl VerifiedEmail {
    /// Returns the verified address for the claims boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VerifiedEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedEmail([REDACTED])")
    }
}

/// Stable subject and current verified identity allocated for an active user.
#[derive(Clone, Debug)]
pub struct AuthorizedSubjectState {
    /// Issuer-local stable subject.
    pub subject: OAuthSubject,
    /// Current verified local email, when present.
    pub verified_email: Option<VerifiedEmail>,
}

/// One-snapshot live authorization result for an issuer access token.
#[derive(Clone, Debug)]
pub struct LiveAccessIdentity {
    /// Current live grant, including resolved tenant membership.
    pub grant: LiveGrant,
    /// Current verified local email, when present.
    pub verified_email: Option<VerifiedEmail>,
}

/// PostgreSQL-backed OAuth protocol store.
#[derive(Clone, Debug)]
pub struct OAuthPostgresStore {
    pool: PostgresPool,
}

impl OAuthPostgresStore {
    /// Creates a store from the shared managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Borrows the shared pool for composition and supervised cleanup.
    #[must_use]
    pub const fn pool(&self) -> &PostgresPool {
        &self.pool
    }

    /// Atomically upserts a client and replaces its exact redirect sets.
    pub async fn upsert_client(
        &self,
        input: &ClientUpsert,
    ) -> Result<RegisteredClient, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self.upsert_client_with(&mut transaction, input).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::upsert_client`].
    pub async fn upsert_client_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &ClientUpsert,
    ) -> Result<RegisteredClient, OAuthStoreError> {
        validate_client_upsert(input)?;
        let response_types = response_type_values(&input.response_types);
        let grant_types = grant_type_values(&input.grant_types);
        let allowed_scopes = scope_values(&input.allowed_scopes)?;
        let (cache_body, cache_etag, cache_modified, cached_at, cache_expires_at) = input
            .metadata_cache
            .as_ref()
            .map_or((None, None, None, None, None), |cache| {
                (
                    Some(cache.body.clone()),
                    cache.etag.as_deref(),
                    cache.last_modified.as_deref(),
                    Some(cache.cached_at),
                    Some(cache.expires_at),
                )
            });
        let id = OAuthClientRecordId::new();
        let client_secret_digest = input
            .client_secret_digest
            .as_ref()
            .map(|digest| digest.as_bytes().as_slice());
        let row = sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, source, status, display_name, client_uri, \
             logo_uri, application_type, token_endpoint_auth_method, client_secret_digest, \
             response_types, grant_types, allowed_scopes, public_jwks, metadata_document_uri, \
             metadata_cache_body, metadata_cache_etag, metadata_cache_last_modified, \
             metadata_cached_at, metadata_cache_expires_at, created_at, updated_at, disabled_at) \
             VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                     $14, $15, $16, $17, $18, $19, $20, $20, NULL) \
             ON CONFLICT (client_id) DO UPDATE SET source = EXCLUDED.source, \
                 display_name = EXCLUDED.display_name, client_uri = EXCLUDED.client_uri, \
                 logo_uri = EXCLUDED.logo_uri, application_type = EXCLUDED.application_type, \
                 token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method, \
                 client_secret_digest = EXCLUDED.client_secret_digest, \
                 response_types = EXCLUDED.response_types, grant_types = EXCLUDED.grant_types, \
                 allowed_scopes = EXCLUDED.allowed_scopes, public_jwks = EXCLUDED.public_jwks, \
                 metadata_document_uri = EXCLUDED.metadata_document_uri, \
                 metadata_cache_body = EXCLUDED.metadata_cache_body, \
                 metadata_cache_etag = EXCLUDED.metadata_cache_etag, \
                 metadata_cache_last_modified = EXCLUDED.metadata_cache_last_modified, \
                 metadata_cached_at = EXCLUDED.metadata_cached_at, \
                 metadata_cache_expires_at = EXCLUDED.metadata_cache_expires_at, \
                 updated_at = EXCLUDED.updated_at \
             WHERE oauth_clients.source <> 'dynamic' AND EXCLUDED.source <> 'dynamic' \
             RETURNING id",
        )
        .bind(id.as_uuid())
        .bind(input.client_id.as_str())
        .bind(input.source.as_str())
        .bind(&input.display_name)
        .bind(input.client_uri.as_deref())
        .bind(input.logo_uri.as_deref())
        .bind(application_type_value(input.application_type))
        .bind(token_auth_method_value(input.token_endpoint_auth_method))
        .bind(client_secret_digest)
        .bind(&response_types)
        .bind(&grant_types)
        .bind(&allowed_scopes)
        .bind(input.public_jwks.as_ref())
        .bind(input.metadata_document_uri.as_deref())
        .bind(cache_body)
        .bind(cache_etag)
        .bind(cache_modified)
        .bind(cached_at)
        .bind(cache_expires_at)
        .bind(input.now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        let persisted_id = oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;

        for redirect in &input.redirect_uris {
            sqlx::query(
                "INSERT INTO oauth_client_redirect_uris (id, client_id, redirect_uri, created_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (client_id, redirect_uri) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(persisted_id.as_uuid())
            .bind(redirect.as_str())
            .bind(input.now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
        }
        let registered_redirect_values = redirect_values(&input.redirect_uris);
        sqlx::query(
            "DELETE FROM oauth_client_redirect_uris WHERE client_id = $1 \
             AND NOT (redirect_uri = ANY($2))",
        )
        .bind(persisted_id.as_uuid())
        .bind(&registered_redirect_values)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;

        for redirect in &input.post_logout_redirect_uris {
            sqlx::query(
                "INSERT INTO oauth_client_post_logout_redirect_uris \
                 (id, client_id, redirect_uri, created_at) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (client_id, redirect_uri) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(persisted_id.as_uuid())
            .bind(redirect.as_str())
            .bind(input.now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
        }
        let post_logout_values = redirect_values(&input.post_logout_redirect_uris);
        sqlx::query(
            "DELETE FROM oauth_client_post_logout_redirect_uris WHERE client_id = $1 \
             AND NOT (redirect_uri = ANY($2))",
        )
        .bind(persisted_id.as_uuid())
        .bind(&post_logout_values)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;

        load_client_by_internal_id(transaction, persisted_id).await
    }

    /// Loads active or disabled safe client metadata by exact client ID.
    pub async fn load_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<RegisteredClient>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = load_client_by_protocol_id(&mut transaction, client_id).await;
        finish(transaction, result).await
    }

    /// Loads authentication material only for an active exact client ID.
    pub async fn load_client_authentication(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ClientAuthentication>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .load_client_authentication_with(&mut transaction, client_id)
            .await;
        finish(transaction, result).await
    }

    /// Loads active authentication material while holding a shared client-row lock.
    pub async fn load_client_authentication_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
    ) -> Result<Option<ClientAuthentication>, OAuthStoreError> {
        let row = sqlx::query(
            "SELECT id, client_id, token_endpoint_auth_method, client_secret_digest, public_jwks \
             FROM oauth_clients WHERE client_id = $1 AND status = 'active' FOR SHARE",
        )
        .bind(client_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        row.as_ref().map(client_authentication_from_row).transpose()
    }

    /// Disables a client and atomically revokes every live grant and refresh family.
    pub async fn disable_client(
        &self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<ClientDisableOutcome>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .disable_client_with(&mut transaction, client_id, now)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::disable_client`].
    pub async fn disable_client_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<ClientDisableOutcome>, OAuthStoreError> {
        let row =
            sqlx::query("SELECT id, status FROM oauth_clients WHERE client_id = $1 FOR UPDATE")
                .bind(client_id.as_str())
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|error| map_db(&error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id = oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        let status: String = row
            .try_get("status")
            .map_err(|_| OAuthStoreError::CorruptData)?;
        let newly_disabled = status == "active";
        if !matches!(status.as_str(), "active" | "disabled") {
            return Err(OAuthStoreError::CorruptData);
        }
        if newly_disabled {
            sqlx::query(
                "UPDATE oauth_clients SET status = 'disabled', disabled_at = $2, updated_at = $2 \
                 WHERE id = $1",
            )
            .bind(id.as_uuid())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
        }
        let grants = sqlx::query(
            "UPDATE oauth_grants SET revoked_at = $2, updated_at = $2, version = version + 1 \
             WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        let families = sqlx::query(
            "UPDATE oauth_refresh_token_families SET revoked_at = $2, \
             revocation_reason = 'client_disabled', version = version + 1 \
             WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        Ok(Some(ClientDisableOutcome {
            newly_disabled,
            grants_revoked: grants,
            refresh_families_revoked: families,
        }))
    }

    /// Atomically records one client assertion replay key before accepting it.
    pub async fn record_client_assertion(
        &self,
        client_id: &ClientId,
        jti: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ClientAssertionRecord, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .record_client_assertion_with(&mut transaction, client_id, jti, issued_at, expires_at)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::record_client_assertion`].
    pub async fn record_client_assertion_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
        jti: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ClientAssertionRecord, OAuthStoreError> {
        if !valid_visible_text(jti, MAX_ASSERTION_JTI_BYTES)
            || expires_at <= issued_at
            || expires_at > issued_at + Duration::minutes(10)
        {
            return Err(OAuthStoreError::InvalidInput);
        }
        let result = sqlx::query(
            "INSERT INTO oauth_client_assertions (id, client_id, jti, issued_at, expires_at) \
             SELECT $1, id, $3, $4, $5 FROM oauth_clients \
             WHERE client_id = $2 AND status = 'active' \
             ON CONFLICT (client_id, jti) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(client_id.as_str())
        .bind(jti)
        .bind(issued_at)
        .bind(expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if result.rows_affected() == 1 {
            return Ok(ClientAssertionRecord::Accepted);
        }
        let active =
            sqlx::query("SELECT 1 FROM oauth_clients WHERE client_id = $1 AND status = 'active'")
                .bind(client_id.as_str())
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|error| map_db(&error))?
                .is_some();
        Ok(if active {
            ClientAssertionRecord::Replay
        } else {
            ClientAssertionRecord::ClientUnavailable
        })
    }

    /// Persists a pending authorization request using only the handle digest.
    pub async fn create_authorization_request(
        &self,
        input: &AuthorizationRequestCreate,
    ) -> Result<AuthorizationRequestId, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .create_authorization_request_with(&mut transaction, input)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::create_authorization_request`].
    pub async fn create_authorization_request_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &AuthorizationRequestCreate,
    ) -> Result<AuthorizationRequestId, OAuthStoreError> {
        validate_authorization_request(input)?;
        let requested_scopes = scope_values(&input.requested_scopes)?;
        let resources = resource_values(&input.resource_uris)?;
        let prompts = prompt_values(&input.prompt_values)?;
        let interaction_scope_descriptions = input
            .interaction_scopes
            .iter()
            .map(|scope| scope.description.as_str())
            .collect::<Vec<_>>();
        let interaction_scope_newly_requested = input
            .interaction_scopes
            .iter()
            .map(|scope| scope.newly_requested)
            .collect::<Vec<_>>();
        let id = AuthorizationRequestId::new();
        let max_age = input
            .max_age_seconds
            .map(i64::try_from)
            .transpose()
            .map_err(|_| OAuthStoreError::InvalidInput)?;
        let result = sqlx::query(
            "INSERT INTO oauth_authorization_requests \
             (id, request_handle_digest, client_id, redirect_uri, response_type, response_mode, \
              client_state, requested_scopes, resource_uris, pkce_code_challenge, nonce, \
              prompt_values, max_age_seconds, expected_issuer, interaction_resource_name, \
              interaction_resource_description, interaction_minimum_assurance, \
              interaction_scope_descriptions, interaction_scope_newly_requested, \
              interaction_requirement, status, created_at, expires_at, completed_at) \
             SELECT $1, $2, client.id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                    $15, $16, $17, $18, $19, $20, 'pending', $21, $22, NULL \
             FROM oauth_clients client JOIN oauth_client_redirect_uris redirect \
               ON redirect.client_id = client.id AND redirect.redirect_uri = $4 \
             WHERE client.client_id = $3 AND client.status = 'active'",
        )
        .bind(id.as_uuid())
        .bind(input.handle_digest.as_bytes().as_slice())
        .bind(input.client_id.as_str())
        .bind(input.redirect_uri.as_str())
        .bind(response_type_value(input.response_type))
        .bind(response_mode_value(input.response_mode))
        .bind(input.client_state.as_deref())
        .bind(&requested_scopes)
        .bind(&resources)
        .bind(input.pkce_code_challenge.as_str())
        .bind(input.nonce.as_deref())
        .bind(&prompts)
        .bind(max_age)
        .bind(input.expected_issuer.as_str())
        .bind(&input.interaction_resource_name)
        .bind(&input.interaction_resource_description)
        .bind(assurance_value(input.interaction_minimum_assurance))
        .bind(&interaction_scope_descriptions)
        .bind(&interaction_scope_newly_requested)
        .bind(input.interaction_requirement.as_db())
        .bind(input.created_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if result.rows_affected() == 1 {
            Ok(id)
        } else {
            Err(OAuthStoreError::Inactive)
        }
    }

    /// Loads a live pending authorization request, atomically expiring it when necessary.
    pub async fn load_authorization_request(
        &self,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<AuthorizationRequestLoad, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = load_authorization_request_with(&mut transaction, digest, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::load_authorization_request`].
    pub async fn load_authorization_request_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<AuthorizationRequestLoad, OAuthStoreError> {
        load_authorization_request_with(transaction, digest, now).await
    }

    /// Atomically applies an approve/deny transition once.
    pub async fn transition_authorization_request(
        &self,
        digest: &BearerDigest,
        decision: AuthorizationDecision,
        now: OffsetDateTime,
    ) -> Result<AuthorizationTransition, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result =
            transition_authorization_request_with(&mut transaction, digest, decision, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::transition_authorization_request`].
    pub async fn transition_authorization_request_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        decision: AuthorizationDecision,
        now: OffsetDateTime,
    ) -> Result<AuthorizationTransition, OAuthStoreError> {
        transition_authorization_request_with(transaction, digest, decision, now).await
    }

    /// Allocates one stable public subject for an active user under concurrency.
    pub async fn allocate_subject(
        &self,
        user_id: SubjectId,
        candidate: PublicSubject,
        now: OffsetDateTime,
    ) -> Result<OAuthSubject, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let row = sqlx::query(
            "INSERT INTO oauth_subjects (id, user_id, public_subject, created_at) \
             SELECT $1, id, $3, $4 FROM users WHERE id = $2 AND status = 'active' \
             ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id \
             RETURNING id, user_id, public_subject, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(user_id.as_uuid())
        .bind(candidate.as_str())
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .ok_or(OAuthStoreError::Inactive)?;
        subject_from_row(&row)
    }

    /// Allocates a stable public subject and reads current verified identity in one snapshot.
    pub async fn authorize_subject(
        &self,
        user_id: SubjectId,
        candidate: PublicSubject,
        local_identity_provider: &str,
        now: OffsetDateTime,
    ) -> Result<AuthorizedSubjectState, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let row = sqlx::query(
                "INSERT INTO oauth_subjects (id, user_id, public_subject, created_at) \
                 SELECT $1, id, $3, $4 FROM users WHERE id = $2 AND status = 'active' \
                 ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id \
                 RETURNING id, user_id, public_subject, created_at",
            )
            .bind(Uuid::now_v7())
            .bind(user_id.as_uuid())
            .bind(candidate.as_str())
            .bind(now)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(OAuthStoreError::Inactive)?;
            let subject = subject_from_row(&row)?;
            let verified_email =
                verified_email_with(&mut transaction, user_id, local_identity_provider).await?;
            Ok(AuthorizedSubjectState {
                subject,
                verified_email,
            })
        }
        .await;
        finish(transaction, result).await
    }

    /// Creates a consent grant after atomically rechecking user, client, and tenant membership.
    pub async fn create_grant(&self, input: &GrantCreate) -> Result<LiveGrant, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self.create_grant_with(&mut transaction, input).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::create_grant`].
    pub async fn create_grant_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &GrantCreate,
    ) -> Result<LiveGrant, OAuthStoreError> {
        validate_grant_create(input)?;
        let resources = resource_values(&input.resources)?;
        let scopes = scope_values(&input.granted_scopes)?;
        let methods = auth_method_values(&input.authentication_methods)?;
        let grant_id = GrantId::new();
        let row = sqlx::query(
            "INSERT INTO oauth_grants \
             (id, subject_id, tenant_id, client_id, resources, granted_scopes, authenticated_at, \
              assurance_level, authentication_methods, consented_at, created_at, updated_at, \
              revoked_at, version) \
             SELECT $1, subject.id, $3, client.id, $5, $6, $7, $8, $9, $10, $10, $10, NULL, 1 \
             FROM oauth_subjects subject \
             JOIN users user_account ON user_account.id = subject.user_id \
             CROSS JOIN oauth_clients client \
             WHERE subject.user_id = $2 AND user_account.status = 'active' \
               AND client.client_id = $4 AND client.status = 'active' \
               AND ($3::uuid IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = $3 AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             FOR SHARE OF subject, user_account, client \
             RETURNING id",
        )
        .bind(grant_id.as_uuid())
        .bind(input.user_id.as_uuid())
        .bind(input.tenant_id.map(TenantId::as_uuid))
        .bind(input.client_id.as_str())
        .bind(&resources)
        .bind(&scopes)
        .bind(input.authenticated_at)
        .bind(assurance_value(input.assurance_level))
        .bind(&methods)
        .bind(input.consented_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if row.is_none() {
            return Err(OAuthStoreError::Inactive);
        }
        load_live_grant(transaction, grant_id)
            .await?
            .ok_or(OAuthStoreError::CorruptData)
    }

    /// Finds the newest live covering grant without broadening resources or scopes.
    pub async fn find_reusable_grant(
        &self,
        user_id: SubjectId,
        tenant_id: Option<TenantId>,
        client_id: &ClientId,
        resources: &[ResourceUri],
        scopes: &[Scope],
    ) -> Result<Option<LiveGrant>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .find_reusable_grant_with(
                &mut transaction,
                user_id,
                tenant_id,
                client_id,
                resources,
                scopes,
            )
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::find_reusable_grant`].
    pub async fn find_reusable_grant_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: SubjectId,
        tenant_id: Option<TenantId>,
        client_id: &ClientId,
        resources: &[ResourceUri],
        scopes: &[Scope],
    ) -> Result<Option<LiveGrant>, OAuthStoreError> {
        let resources = resource_values(resources)?;
        let scopes = scope_values(scopes)?;
        let row = sqlx::query(
            "SELECT grant_row.id FROM oauth_grants grant_row \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             WHERE subject.user_id = $1 AND grant_row.tenant_id IS NOT DISTINCT FROM $2 \
               AND client.client_id = $3 AND user_account.status = 'active' \
               AND client.status = 'active' AND grant_row.revoked_at IS NULL \
               AND grant_row.resources @> $4 AND grant_row.granted_scopes @> $5 \
               AND ($2::uuid IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = $2 AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             ORDER BY grant_row.created_at DESC, grant_row.id DESC LIMIT 1 FOR SHARE OF grant_row",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.map(TenantId::as_uuid))
        .bind(client_id.as_str())
        .bind(&resources)
        .bind(&scopes)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grant_id = grant_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        load_live_grant(transaction, grant_id).await
    }

    /// Revokes an owned grant and every active refresh family atomically.
    pub async fn revoke_grant(
        &self,
        user_id: SubjectId,
        grant_id: GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = revoke_grant_with(&mut transaction, user_id, grant_id, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::revoke_grant`].
    pub async fn revoke_grant_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: SubjectId,
        grant_id: GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        revoke_grant_with(transaction, user_id, grant_id, now).await
    }

    /// Lists bounded safe connected-application metadata for one active user.
    pub async fn list_connected_grants(
        &self,
        user_id: SubjectId,
        cursor: Option<GrantCursor>,
        limit: u16,
    ) -> Result<ConnectedGrantPage, OAuthStoreError> {
        if limit == 0 || limit > MAX_LIST_LIMIT {
            return Err(OAuthStoreError::InvalidInput);
        }
        let fetch_limit = i64::from(limit) + 1;
        let (cursor_created_at, cursor_id) = cursor.map_or((None, None), |cursor| {
            (Some(cursor.created_at), Some(cursor.id.as_uuid()))
        });
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT grant_row.id, grant_row.tenant_id, grant_row.resources, \
                    grant_row.granted_scopes, grant_row.consented_at, grant_row.created_at, \
                    client.client_id, client.display_name, client.client_uri, client.logo_uri \
             FROM oauth_grants grant_row \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             WHERE subject.user_id = $1 AND user_account.status = 'active' \
               AND grant_row.revoked_at IS NULL AND client.status = 'active' \
               AND ($2::timestamptz IS NULL OR (grant_row.created_at, grant_row.id) < ($2, $3)) \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             ORDER BY grant_row.created_at DESC, grant_row.id DESC LIMIT $4",
        )
        .bind(user_id.as_uuid())
        .bind(cursor_created_at)
        .bind(cursor_id)
        .bind(fetch_limit)
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        let mut grants = rows
            .iter()
            .map(connected_grant_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = grants.len() > usize::from(limit);
        if has_more {
            grants.truncate(usize::from(limit));
        }
        let next = if has_more {
            grants.last().map(|grant| GrantCursor {
                created_at: grant.created_at,
                id: grant.grant_id,
            })
        } else {
            None
        };
        Ok(ConnectedGrantPage { grants, next })
    }

    /// Persists a short-lived authorization code using only its digest.
    pub async fn persist_authorization_code(
        &self,
        input: &AuthorizationCodeCreate,
    ) -> Result<(), OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .persist_authorization_code_with(&mut transaction, input)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::persist_authorization_code`].
    pub async fn persist_authorization_code_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &AuthorizationCodeCreate,
    ) -> Result<(), OAuthStoreError> {
        validate_authorization_code(input)?;
        let resources = resource_values(&input.resource_uris)?;
        let scopes = scope_values(&input.granted_scopes)?;
        let result = sqlx::query(
            "INSERT INTO oauth_authorization_codes \
             (id, code_digest, grant_id, client_id, redirect_uri, resource_uris, granted_scopes, \
              pkce_code_challenge, nonce, issued_at, expires_at, consumed_at, exchange_outcome) \
             SELECT $1, $2, grant_row.id, client.id, $5, $6, $7, $8, $9, $10, $11, NULL, NULL \
             FROM oauth_grants grant_row JOIN oauth_clients client ON client.id = grant_row.client_id \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             WHERE grant_row.id = $3 AND client.client_id = $4 AND grant_row.revoked_at IS NULL \
               AND client.status = 'active' AND user_account.status = 'active' \
               AND grant_row.resources @> $6 AND grant_row.granted_scopes @> $7 \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             FOR SHARE OF grant_row, client, subject, user_account",
        )
        .bind(Uuid::now_v7())
        .bind(input.code_digest.as_bytes().as_slice())
        .bind(input.grant_id.as_uuid())
        .bind(input.client_id.as_str())
        .bind(input.redirect_uri.as_str())
        .bind(&resources)
        .bind(&scopes)
        .bind(input.pkce_code_challenge.as_str())
        .bind(input.nonce.as_deref())
        .bind(input.issued_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(OAuthStoreError::Inactive)
        }
    }

    /// Atomically consumes a recognized code before reporting any binding or liveness failure.
    pub async fn consume_authorization_code(
        &self,
        digest: &BearerDigest,
        binding: &AuthorizationCodeBinding,
        now: OffsetDateTime,
    ) -> Result<AuthorizationCodeExchange, OAuthStoreError> {
        let resources = resource_values(&binding.resource_uris)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result =
            consume_authorization_code_with(&mut transaction, digest, binding, &resources, now)
                .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::consume_authorization_code`].
    pub async fn consume_authorization_code_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        binding: &AuthorizationCodeBinding,
        now: OffsetDateTime,
    ) -> Result<AuthorizationCodeExchange, OAuthStoreError> {
        let resources = resource_values(&binding.resource_uris)?;
        consume_authorization_code_with(transaction, digest, binding, &resources, now).await
    }

    /// Issues the first refresh token in a new family atomically.
    pub async fn issue_refresh_family(
        &self,
        input: &RefreshFamilyIssue,
    ) -> Result<IssuedRefreshToken, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .issue_refresh_family_with(&mut transaction, input)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::issue_refresh_family`].
    pub async fn issue_refresh_family_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &RefreshFamilyIssue,
    ) -> Result<IssuedRefreshToken, OAuthStoreError> {
        if input.expires_at <= input.issued_at
            || input.expires_at > input.issued_at + Duration::days(90)
            || input.granted_scopes.is_empty()
        {
            return Err(OAuthStoreError::InvalidInput);
        }
        let granted_scopes = scope_values(&input.granted_scopes)?;
        let family_id = RefreshFamilyId::new();
        let token_id = RefreshTokenId::new();
        let coordinates = sqlx::query(
            "SELECT grant_row.resources, grant_row.granted_scopes \
             FROM oauth_grants grant_row \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             WHERE grant_row.id = $1 AND client.client_id = $2 AND grant_row.revoked_at IS NULL \
               AND client.status = 'active' AND user_account.status = 'active' \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             FOR SHARE OF grant_row, client, subject, user_account",
        )
        .bind(input.grant_id.as_uuid())
        .bind(input.client_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        let Some(coordinates) = coordinates else {
            return Err(OAuthStoreError::Inactive);
        };
        let resources = parse_resources(
            coordinates
                .try_get("resources")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        let grant_scopes = parse_scopes(
            coordinates
                .try_get("granted_scopes")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        if !resources.contains(&input.resource)
            || input
                .granted_scopes
                .iter()
                .any(|scope| grant_scopes.binary_search(scope).is_err())
        {
            return Err(OAuthStoreError::Inactive);
        }
        let client_internal_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oauth_clients WHERE client_id = $1 AND status = 'active'",
        )
        .bind(input.client_id.as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        sqlx::query(
            "INSERT INTO oauth_refresh_token_families \
             (id, grant_id, client_id, resource_uri, granted_scopes, created_at, expires_at, \
              revoked_at, revocation_reason, reuse_detected_at, version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, 1)",
        )
        .bind(family_id.as_uuid())
        .bind(input.grant_id.as_uuid())
        .bind(client_internal_id)
        .bind(input.resource.as_str())
        .bind(&granted_scopes)
        .bind(input.issued_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        sqlx::query(
            "INSERT INTO oauth_refresh_tokens \
             (id, family_id, grant_id, token_digest, rotation_sequence, issued_at, expires_at, \
              consumed_at, replaced_by_id, revoked_at, reuse_detected_at) \
             VALUES ($1, $2, $3, $4, 0, $5, $6, NULL, NULL, NULL, NULL)",
        )
        .bind(token_id.as_uuid())
        .bind(family_id.as_uuid())
        .bind(input.grant_id.as_uuid())
        .bind(input.token_digest.as_bytes().as_slice())
        .bind(input.issued_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(IssuedRefreshToken {
            family_id,
            token_id,
            rotation_sequence: 0,
            expires_at: input.expires_at,
        })
    }

    /// Rotates a refresh token, or atomically revokes its family and grant on reuse.
    pub async fn rotate_refresh_token(
        &self,
        digest: &BearerDigest,
        client_id: &ClientId,
        replacement_digest: &BearerDigest,
        now: OffsetDateTime,
        replacement_expires_at: OffsetDateTime,
    ) -> Result<RefreshRotation, OAuthStoreError> {
        if replacement_expires_at <= now {
            return Err(OAuthStoreError::InvalidInput);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = rotate_refresh_token_with(
            &mut transaction,
            digest,
            client_id,
            replacement_digest,
            now,
            replacement_expires_at,
        )
        .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::rotate_refresh_token`].
    pub async fn rotate_refresh_token_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        client_id: &ClientId,
        replacement_digest: &BearerDigest,
        now: OffsetDateTime,
        replacement_expires_at: OffsetDateTime,
    ) -> Result<RefreshRotation, OAuthStoreError> {
        if replacement_expires_at <= now {
            return Err(OAuthStoreError::InvalidInput);
        }
        rotate_refresh_token_with(
            transaction,
            digest,
            client_id,
            replacement_digest,
            now,
            replacement_expires_at,
        )
        .await
    }

    /// RFC 7009 refresh-token revocation. Unknown digests remain a successful no-op.
    pub async fn revoke_refresh_token(
        &self,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = revoke_refresh_token_with(&mut transaction, digest, None, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::revoke_refresh_token`].
    pub async fn revoke_refresh_token_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        revoke_refresh_token_with(transaction, digest, None, now).await
    }

    /// Revokes a refresh family only when it belongs to the authenticated client.
    pub async fn revoke_refresh_token_for_client_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        revoke_refresh_token_with(transaction, digest, Some(client_id), now).await
    }

    /// Records one access-token `jti` revocation idempotently through token expiry.
    pub async fn revoke_access_token(
        &self,
        input: &AccessTokenRevocation,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self.revoke_access_token_with(&mut transaction, input).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::revoke_access_token`].
    pub async fn revoke_access_token_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &AccessTokenRevocation,
    ) -> Result<bool, OAuthStoreError> {
        if input.revoked_at < input.issued_at || input.expires_at <= input.revoked_at {
            return Err(OAuthStoreError::InvalidInput);
        }
        let result = sqlx::query(
            "INSERT INTO oauth_access_token_revocations \
             (jti, grant_id, client_id, issued_at, expires_at, revoked_at, reason) \
             SELECT $1, grant_row.id, client.id, $4, $5, $6, $7 \
             FROM oauth_grants grant_row JOIN oauth_clients client ON client.id = grant_row.client_id \
             WHERE grant_row.id = $2 AND client.client_id = $3 \
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(input.jti.as_uuid())
        .bind(input.grant_id.as_uuid())
        .bind(input.client_id.as_str())
        .bind(input.issued_at)
        .bind(input.expires_at)
        .bind(input.revoked_at)
        .bind(input.reason.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(result.rows_affected() == 1)
    }

    /// Revokes a verified issuer JTI for the configured maximum one-hour token lifetime.
    pub async fn revoke_access_token_jti_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        jti: JwtId,
        grant_id: GrantId,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        self.revoke_access_token_with(
            transaction,
            &AccessTokenRevocation {
                jti,
                grant_id,
                client_id: client_id.clone(),
                issued_at: now,
                expires_at: now + Duration::hours(1),
                revoked_at: now,
                reason: AccessRevocationReason::TokenRevoked,
            },
        )
        .await
    }

    /// Rechecks live authorization state and returns the durable grant.
    pub async fn verify_access_token_live(
        &self,
        check: &AccessTokenLiveCheck,
        now: OffsetDateTime,
    ) -> Result<Option<LiveGrant>, OAuthStoreError> {
        self.verify_access_token_live_identity(check, "local", now)
            .await
            .map(|identity| identity.map(|identity| identity.grant))
    }

    /// One-snapshot live authorization and verified local-identity read.
    pub async fn verify_access_token_live_identity(
        &self,
        check: &AccessTokenLiveCheck,
        local_identity_provider: &str,
        now: OffsetDateTime,
    ) -> Result<Option<LiveAccessIdentity>, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        let scopes = scope_values(&check.scopes)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let row = sqlx::query(
            "SELECT grant_row.id, subject.public_subject, subject.user_id, grant_row.tenant_id, \
                    client.client_id, grant_row.resources, grant_row.granted_scopes, \
                    grant_row.authenticated_at, grant_row.assurance_level, \
                    grant_row.authentication_methods, grant_row.consented_at, grant_row.version, \
                    verified_identity.provider_subject AS verified_email \
             FROM oauth_grants grant_row \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             LEFT JOIN LATERAL ( \
                 SELECT identity.provider_subject FROM identities identity \
                 WHERE identity.user_id = subject.user_id AND identity.provider = $7 \
                   AND identity.verified_at IS NOT NULL \
                 ORDER BY identity.created_at, identity.id LIMIT 1 \
             ) verified_identity ON true \
             WHERE grant_row.id = $1 AND subject.public_subject = $2 AND client.client_id = $3 \
               AND $4 = ANY(grant_row.resources) AND grant_row.granted_scopes @> $5 \
               AND grant_row.revoked_at IS NULL AND user_account.status = 'active' \
               AND client.status = 'active' \
               AND NOT EXISTS (SELECT 1 FROM oauth_access_token_revocations revocation \
                               WHERE revocation.jti = $6 AND revocation.expires_at > $8) \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active'))",
        )
        .bind(check.grant_id.as_uuid())
        .bind(check.public_subject.as_str())
        .bind(check.client_id.as_str())
        .bind(check.resource.as_str())
        .bind(&scopes)
        .bind(check.jti.as_uuid())
        .bind(local_identity_provider)
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        row.as_ref()
            .map(|row| {
                Ok(LiveAccessIdentity {
                    grant: live_grant_from_row(row)?,
                    verified_email: row
                        .try_get::<Option<String>, _>("verified_email")
                        .map_err(|_| OAuthStoreError::CorruptData)?
                        .map(VerifiedEmail),
                })
            })
            .transpose()
    }

    /// Returns a verified local email only for an active user.
    pub async fn verified_email(
        &self,
        user_id: SubjectId,
        local_identity_provider: &str,
    ) -> Result<Option<VerifiedEmail>, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = verified_email_with(&mut transaction, user_id, local_identity_provider).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::verified_email`].
    pub async fn verified_email_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: SubjectId,
        local_identity_provider: &str,
    ) -> Result<Option<VerifiedEmail>, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        verified_email_with(transaction, user_id, local_identity_provider).await
    }

    /// Confirms that an active internal user owns an issuer-local public subject.
    pub async fn public_subject_matches(
        &self,
        user_id: SubjectId,
        public_subject: &str,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let matched: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM oauth_subjects subject \
                 JOIN users user_account ON user_account.id = subject.user_id \
                 WHERE subject.user_id = $1 AND subject.public_subject = $2 \
                   AND user_account.status = 'active')",
        )
        .bind(user_id.as_uuid())
        .bind(public_subject)
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(matched)
    }
}

async fn verified_email_with(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
    local_identity_provider: &str,
) -> Result<Option<VerifiedEmail>, OAuthStoreError> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT identity.provider_subject FROM identities identity \
         JOIN users user_account ON user_account.id = identity.user_id \
         WHERE identity.user_id = $1 AND identity.provider = $2 \
           AND identity.verified_at IS NOT NULL AND user_account.status = 'active' \
         ORDER BY identity.created_at, identity.id LIMIT 1",
    )
    .bind(user_id.as_uuid())
    .bind(local_identity_provider)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(value.map(VerifiedEmail))
}

/// Stable, value-free OAuth persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OAuthStoreError {
    /// A caller violated a bounded persistence input contract.
    #[error("OAuth persistence input is invalid")]
    InvalidInput,
    /// A unique or exact-state transition conflicted.
    #[error("OAuth persistence transition conflicts with existing state")]
    Conflict,
    /// Required durable state does not exist.
    #[error("OAuth persistence state was not found")]
    NotFound,
    /// A required user, client, grant, or tenant binding is inactive.
    #[error("OAuth persistence state is inactive")]
    Inactive,
    /// Durable state violated the module schema contract.
    #[error("OAuth persistence state is corrupt")]
    CorruptData,
    /// PostgreSQL is unavailable.
    #[error("OAuth persistence is unavailable")]
    Unavailable,
    /// A retry-safe SQL conflict occurred.
    #[error("OAuth persistence encountered a transient conflict")]
    Transient(RetryableSqlState),
}

impl RetryableTransactionError for OAuthStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

async fn load_authorization_request_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    now: OffsetDateTime,
) -> Result<AuthorizationRequestLoad, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT request.id, request.client_id AS internal_client_id, request.redirect_uri, \
                request.response_type, request.response_mode, request.client_state, \
                request.requested_scopes, request.resource_uris, request.pkce_code_challenge, \
                request.nonce, request.prompt_values, request.max_age_seconds, \
                request.expected_issuer, request.interaction_resource_name, \
                request.interaction_resource_description, request.interaction_minimum_assurance, \
                request.interaction_scope_descriptions, request.interaction_scope_newly_requested, \
                request.interaction_requirement, request.status, request.created_at, \
                request.expires_at, request.completed_at, client.status AS client_status \
         FROM oauth_authorization_requests request \
         JOIN oauth_clients client ON client.id = request.client_id \
         WHERE request.request_handle_digest = $1 FOR UPDATE OF request",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(AuthorizationRequestLoad::Unavailable);
    };
    let status: String = row
        .try_get("status")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let client_status: String = row
        .try_get("client_status")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if status != "pending" || client_status != "active" {
        return Ok(AuthorizationRequestLoad::Unavailable);
    }
    let expires_at: OffsetDateTime = row
        .try_get("expires_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if now >= expires_at {
        sqlx::query(
            "UPDATE oauth_authorization_requests SET status = 'expired', completed_at = $2 \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(
            row.try_get::<Uuid, _>("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        return Ok(AuthorizationRequestLoad::Expired);
    }
    let internal_id = oauth_client_id(
        row.try_get("internal_client_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let client = load_client_by_internal_id(transaction, internal_id).await?;
    Ok(AuthorizationRequestLoad::Pending(
        authorization_request_from_row(&row, client)?,
    ))
}

async fn transition_authorization_request_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    decision: AuthorizationDecision,
    now: OffsetDateTime,
) -> Result<AuthorizationTransition, OAuthStoreError> {
    match load_authorization_request_with(transaction, digest, now).await? {
        AuthorizationRequestLoad::Expired => Ok(AuthorizationTransition::Expired),
        AuthorizationRequestLoad::Unavailable => Ok(AuthorizationTransition::Unavailable),
        AuthorizationRequestLoad::Pending(mut request) => {
            let result = sqlx::query(
                "UPDATE oauth_authorization_requests SET status = $2, completed_at = $3 \
                 WHERE id = $1 AND status = 'pending'",
            )
            .bind(request.id.as_uuid())
            .bind(decision.status())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
            if result.rows_affected() != 1 {
                return Ok(AuthorizationTransition::Unavailable);
            }
            request.status = match decision {
                AuthorizationDecision::Approve => AuthorizationRequestStatus::Approved,
                AuthorizationDecision::Deny => AuthorizationRequestStatus::Denied,
            };
            request.completed_at = Some(now);
            Ok(AuthorizationTransition::Completed(request))
        }
    }
}

async fn revoke_grant_with(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
    grant_id: GrantId,
    now: OffsetDateTime,
) -> Result<bool, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT grant_row.revoked_at FROM oauth_grants grant_row \
         JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
         WHERE grant_row.id = $1 AND subject.user_id = $2 FOR UPDATE OF grant_row",
    )
    .bind(grant_id.as_uuid())
    .bind(user_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(false);
    };
    let revoked_at: Option<OffsetDateTime> = row
        .try_get("revoked_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if revoked_at.is_none() {
        sqlx::query(
            "UPDATE oauth_grants SET revoked_at = $2, updated_at = $2, version = version + 1 \
             WHERE id = $1",
        )
        .bind(grant_id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    }
    sqlx::query(
        "UPDATE oauth_refresh_token_families SET revoked_at = $2, \
         revocation_reason = 'grant_revoked', version = version + 1 \
         WHERE grant_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(true)
}

async fn consume_authorization_code_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    binding: &AuthorizationCodeBinding,
    resource_values: &[String],
    now: OffsetDateTime,
) -> Result<AuthorizationCodeExchange, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT code.id, code.grant_id, code.redirect_uri, code.resource_uris, \
                code.granted_scopes, code.pkce_code_challenge, code.nonce, code.issued_at, \
                code.expires_at, client.client_id, client.status AS client_status, \
                grant_row.resources AS grant_resources, \
                grant_row.granted_scopes AS grant_scopes \
         FROM oauth_authorization_codes code JOIN oauth_clients client ON client.id = code.client_id \
         JOIN oauth_grants grant_row ON grant_row.id = code.grant_id \
         WHERE code.code_digest = $1 AND code.consumed_at IS NULL FOR UPDATE OF code",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(AuthorizationCodeExchange::Unavailable);
    };
    let code_id: Uuid = row
        .try_get("id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let issued_at: OffsetDateTime = row
        .try_get("issued_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if now < issued_at {
        return Err(OAuthStoreError::InvalidInput);
    }
    let expires_at: OffsetDateTime = row
        .try_get("expires_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let stored_client_id: String = row
        .try_get("client_id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let stored_redirect: String = row
        .try_get("redirect_uri")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let stored_resources: Vec<String> = row
        .try_get("resource_uris")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let stored_challenge: String = row
        .try_get("pkce_code_challenge")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let client_status: String = row
        .try_get("client_status")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let stored_scopes: Vec<String> = row
        .try_get("granted_scopes")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let grant_resources: Vec<String> = row
        .try_get("grant_resources")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let grant_scopes: Vec<String> = row
        .try_get("grant_scopes")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let stored_binding_within_grant = sorted_subset(&stored_resources, &grant_resources)
        && sorted_subset(&stored_scopes, &grant_scopes);
    let binding_matches = stored_client_id == binding.client_id.as_str()
        && stored_redirect == binding.redirect_uri.as_str()
        && stored_resources == resource_values
        && stored_challenge == binding.pkce_verifier.challenge().as_str();
    let grant_id = grant_id(
        row.try_get("grant_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let live_grant = if client_status == "active" {
        load_live_grant(transaction, grant_id).await?
    } else {
        None
    };
    let rejection = if now >= expires_at {
        Some(AuthorizationCodeRejection::Expired)
    } else if !stored_binding_within_grant {
        Some(AuthorizationCodeRejection::StoredBindingViolation)
    } else if !binding_matches {
        Some(AuthorizationCodeRejection::BindingMismatch)
    } else if live_grant.is_none() {
        Some(AuthorizationCodeRejection::Inactive)
    } else {
        None
    };
    sqlx::query(
        "UPDATE oauth_authorization_codes SET consumed_at = $2, exchange_outcome = $3 WHERE id = $1",
    )
    .bind(code_id)
    .bind(now)
    .bind(if rejection.is_some() { "rejected" } else { "issued" })
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    if let Some(rejection) = rejection {
        return Ok(AuthorizationCodeExchange::Rejected(rejection));
    }
    let grant = live_grant.ok_or(OAuthStoreError::CorruptData)?;
    let redirect_uri =
        RedirectUri::parse(stored_redirect).map_err(|_| OAuthStoreError::CorruptData)?;
    let resources = parse_resources(stored_resources)?;
    let scopes = parse_scopes(stored_scopes)?;
    Ok(AuthorizationCodeExchange::Issued(
        ConsumedAuthorizationCode {
            grant,
            redirect_uri,
            resource_uris: resources,
            granted_scopes: scopes,
            nonce: row
                .try_get("nonce")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        },
    ))
}

async fn rotate_refresh_token_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    client_id: &ClientId,
    replacement_digest: &BearerDigest,
    now: OffsetDateTime,
    replacement_expires_at: OffsetDateTime,
) -> Result<RefreshRotation, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT token.id, token.family_id, token.grant_id, token.rotation_sequence, token.issued_at, \
                token.expires_at AS token_expires_at, token.consumed_at, token.revoked_at, \
                family.resource_uri, family.granted_scopes, family.expires_at AS family_expires_at, \
                family.revoked_at AS family_revoked_at, client.client_id \
         FROM oauth_refresh_tokens token \
         JOIN oauth_refresh_token_families family ON family.id = token.family_id \
         JOIN oauth_clients client ON client.id = family.client_id \
         WHERE token.token_digest = $1 FOR UPDATE OF token, family",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(RefreshRotation::Rejected(RefreshRejection::Unknown));
    };
    let token_id = refresh_token_id(
        row.try_get("id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let family_id = refresh_family_id(
        row.try_get("family_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let grant_id = grant_id(
        row.try_get("grant_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let consumed_at: Option<OffsetDateTime> = row
        .try_get("consumed_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let token_revoked_at: Option<OffsetDateTime> = row
        .try_get("revoked_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let family_revoked_at: Option<OffsetDateTime> = row
        .try_get("family_revoked_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if consumed_at.is_some() || token_revoked_at.is_some() || family_revoked_at.is_some() {
        revoke_reused_family(
            transaction,
            token_id,
            family_id,
            grant_id,
            consumed_at.is_some(),
            now,
        )
        .await?;
        return Ok(RefreshRotation::ReuseDetected {
            family_id,
            grant_id,
        });
    }
    let stored_client_id: String = row
        .try_get("client_id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if stored_client_id != client_id.as_str() {
        return Ok(RefreshRotation::Rejected(RefreshRejection::ClientMismatch));
    }
    let issued_at: OffsetDateTime = row
        .try_get("issued_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if now < issued_at {
        return Err(OAuthStoreError::InvalidInput);
    }
    let token_expires_at: OffsetDateTime = row
        .try_get("token_expires_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let family_expires_at: OffsetDateTime = row
        .try_get("family_expires_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if now >= token_expires_at || now >= family_expires_at {
        return Ok(RefreshRotation::Rejected(RefreshRejection::Expired));
    }
    let replacement_expires_at = replacement_expires_at.min(family_expires_at);
    let Some(grant) = load_live_grant(transaction, grant_id).await? else {
        return Ok(RefreshRotation::Rejected(RefreshRejection::Inactive));
    };
    let resource = ResourceUri::parse(
        row.try_get::<String, _>("resource_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        false,
    )
    .map_err(|_| OAuthStoreError::CorruptData)?;
    let granted_scopes = parse_scopes(
        row.try_get("granted_scopes")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    if granted_scopes
        .iter()
        .any(|scope| grant.granted_scopes.binary_search(scope).is_err())
        || !grant.resources.contains(&resource)
    {
        return Err(OAuthStoreError::CorruptData);
    }
    let sequence: i64 = row
        .try_get("rotation_sequence")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let replacement_sequence = sequence
        .checked_add(1)
        .ok_or(OAuthStoreError::CorruptData)?;
    let replacement_id = RefreshTokenId::new();
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens \
         (id, family_id, grant_id, token_digest, rotation_sequence, issued_at, expires_at, \
          consumed_at, replaced_by_id, revoked_at, reuse_detected_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, NULL)",
    )
    .bind(replacement_id.as_uuid())
    .bind(family_id.as_uuid())
    .bind(grant_id.as_uuid())
    .bind(replacement_digest.as_bytes().as_slice())
    .bind(replacement_sequence)
    .bind(now)
    .bind(replacement_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET consumed_at = $2, replaced_by_id = $3 WHERE id = $1",
    )
    .bind(token_id.as_uuid())
    .bind(now)
    .bind(replacement_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query("UPDATE oauth_refresh_token_families SET version = version + 1 WHERE id = $1")
        .bind(family_id.as_uuid())
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    Ok(RefreshRotation::Rotated(RotatedRefreshToken {
        grant,
        resource,
        granted_scopes,
        family_id,
        token_id: replacement_id,
        rotation_sequence: replacement_sequence,
        expires_at: replacement_expires_at,
    }))
}

async fn revoke_reused_family(
    transaction: &mut Transaction<'_, Postgres>,
    presented_token_id: RefreshTokenId,
    family_id: RefreshFamilyId,
    grant_id: GrantId,
    token_was_consumed: bool,
    now: OffsetDateTime,
) -> Result<(), OAuthStoreError> {
    if token_was_consumed {
        sqlx::query("UPDATE oauth_refresh_tokens SET reuse_detected_at = $2 WHERE id = $1")
            .bind(presented_token_id.as_uuid())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
    }
    sqlx::query(
        "UPDATE oauth_refresh_token_families SET revoked_at = COALESCE(revoked_at, $2), \
         revocation_reason = 'refresh_reuse', reuse_detected_at = $2, version = version + 1 \
         WHERE id = $1",
    )
    .bind(family_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = $2 \
         WHERE family_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at = COALESCE(revoked_at, $2), updated_at = $2, \
         version = version + 1 WHERE id = $1",
    )
    .bind(grant_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(())
}

async fn revoke_refresh_token_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    client_id: Option<&ClientId>,
    now: OffsetDateTime,
) -> Result<bool, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT token.family_id, token.grant_id FROM oauth_refresh_tokens token \
         JOIN oauth_refresh_token_families family ON family.id = token.family_id \
         JOIN oauth_clients client ON client.id = family.client_id \
         WHERE token.token_digest = $1 AND ($2::text IS NULL OR client.client_id = $2) \
         FOR UPDATE OF token, family",
    )
    .bind(digest.as_bytes().as_slice())
    .bind(client_id.map(ClientId::as_str))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(false);
    };
    let family_id: Uuid = row
        .try_get("family_id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let grant_id: Uuid = row
        .try_get("grant_id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    sqlx::query(
        "UPDATE oauth_refresh_token_families SET revoked_at = $2, \
         revocation_reason = 'token_revoked', version = version + 1 \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = $2 \
         WHERE family_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at = COALESCE(revoked_at, $2), updated_at = $2, \
         version = version + 1 WHERE id = $1",
    )
    .bind(grant_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(true)
}

async fn load_live_grant(
    transaction: &mut Transaction<'_, Postgres>,
    grant_id: GrantId,
) -> Result<Option<LiveGrant>, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT grant_row.id, subject.public_subject, subject.user_id, grant_row.tenant_id, \
                client.client_id, grant_row.resources, grant_row.granted_scopes, \
                grant_row.authenticated_at, grant_row.assurance_level, \
                grant_row.authentication_methods, grant_row.consented_at, grant_row.version \
         FROM oauth_grants grant_row \
         JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
         JOIN users user_account ON user_account.id = subject.user_id \
         JOIN oauth_clients client ON client.id = grant_row.client_id \
         WHERE grant_row.id = $1 AND grant_row.revoked_at IS NULL \
           AND user_account.status = 'active' AND client.status = 'active' \
           AND (grant_row.tenant_id IS NULL OR EXISTS ( \
               SELECT 1 FROM organizations organization \
               JOIN memberships membership ON membership.organization_id = organization.id \
               WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                 AND membership.user_id = subject.user_id AND membership.status = 'active'))",
    )
    .bind(grant_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    row.as_ref().map(live_grant_from_row).transpose()
}

async fn load_client_by_protocol_id(
    transaction: &mut Transaction<'_, Postgres>,
    client_id: &ClientId,
) -> Result<Option<RegisteredClient>, OAuthStoreError> {
    let row = sqlx::query("SELECT id FROM oauth_clients WHERE client_id = $1")
        .bind(client_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id = oauth_client_id(
        row.try_get("id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    load_client_by_internal_id(transaction, id).await.map(Some)
}

async fn load_client_by_internal_id(
    transaction: &mut Transaction<'_, Postgres>,
    id: OAuthClientRecordId,
) -> Result<RegisteredClient, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT id, client_id, source, status, display_name, client_uri, logo_uri, \
                application_type, token_endpoint_auth_method, response_types, grant_types, \
                allowed_scopes, public_jwks, metadata_cache_expires_at, created_at, updated_at, \
                disabled_at FROM oauth_clients WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let redirect_rows = sqlx::query(
        "SELECT redirect_uri FROM oauth_client_redirect_uris WHERE client_id = $1 \
         ORDER BY redirect_uri COLLATE \"C\"",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let logout_rows = sqlx::query(
        "SELECT redirect_uri FROM oauth_client_post_logout_redirect_uris WHERE client_id = $1 \
         ORDER BY redirect_uri COLLATE \"C\"",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    registered_client_from_rows(&row, &redirect_rows, &logout_rows)
}

fn registered_client_from_rows(
    row: &PgRow,
    redirect_rows: &[PgRow],
    logout_rows: &[PgRow],
) -> Result<RegisteredClient, OAuthStoreError> {
    let response_types: Vec<String> = row
        .try_get("response_types")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let grant_types: Vec<String> = row
        .try_get("grant_types")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let allowed_scopes: Vec<String> = row
        .try_get("allowed_scopes")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    Ok(RegisteredClient {
        id: oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        source: ClientSource::from_db(
            &row.try_get::<String, _>("source")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        status: ClientStatus::from_db(
            &row.try_get::<String, _>("status")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_uri: row
            .try_get("client_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        logo_uri: row
            .try_get("logo_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        application_type: parse_application_type(
            &row.try_get::<String, _>("application_type")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        token_endpoint_auth_method: parse_token_auth_method(
            &row.try_get::<String, _>("token_endpoint_auth_method")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        response_types: response_types
            .into_iter()
            .map(|value| parse_response_type(&value))
            .collect::<Result<Vec<_>, _>>()?,
        grant_types: grant_types
            .into_iter()
            .map(|value| parse_grant_type(&value))
            .collect::<Result<Vec<_>, _>>()?,
        allowed_scopes: allowed_scopes
            .into_iter()
            .map(|value| Scope::new(value).map_err(|_| OAuthStoreError::CorruptData))
            .collect::<Result<Vec<_>, _>>()?,
        public_jwks: row
            .try_get("public_jwks")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        redirect_uris: redirect_rows
            .iter()
            .map(|redirect| {
                RedirectUri::parse(
                    redirect
                        .try_get::<String, _>("redirect_uri")
                        .map_err(|_| OAuthStoreError::CorruptData)?,
                )
                .map_err(|_| OAuthStoreError::CorruptData)
            })
            .collect::<Result<Vec<_>, _>>()?,
        post_logout_redirect_uris: logout_rows
            .iter()
            .map(|redirect| {
                RedirectUri::parse(
                    redirect
                        .try_get::<String, _>("redirect_uri")
                        .map_err(|_| OAuthStoreError::CorruptData)?,
                )
                .map_err(|_| OAuthStoreError::CorruptData)
            })
            .collect::<Result<Vec<_>, _>>()?,
        metadata_cache_expires_at: row
            .try_get("metadata_cache_expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        disabled_at: row
            .try_get("disabled_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn client_authentication_from_row(row: &PgRow) -> Result<ClientAuthentication, OAuthStoreError> {
    let digest: Option<Vec<u8>> = row
        .try_get("client_secret_digest")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    Ok(ClientAuthentication {
        id: oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        method: parse_token_auth_method(
            &row.try_get::<String, _>("token_endpoint_auth_method")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_secret_digest: digest.map(digest_from_vec).transpose()?,
        public_jwks: row
            .try_get("public_jwks")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn authorization_request_from_row(
    row: &PgRow,
    client: RegisteredClient,
) -> Result<AuthorizationRequestRecord, OAuthStoreError> {
    let max_age: Option<i64> = row
        .try_get("max_age_seconds")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let requested_scopes = parse_scopes(
        row.try_get("requested_scopes")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let interaction_scope_descriptions: Vec<String> = row
        .try_get("interaction_scope_descriptions")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let interaction_scope_newly_requested: Vec<bool> = row
        .try_get("interaction_scope_newly_requested")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if interaction_scope_descriptions.len() != requested_scopes.len()
        || interaction_scope_newly_requested.len() != requested_scopes.len()
    {
        return Err(OAuthStoreError::CorruptData);
    }
    let interaction_scopes = requested_scopes
        .iter()
        .cloned()
        .zip(interaction_scope_descriptions)
        .zip(interaction_scope_newly_requested)
        .map(
            |((name, description), newly_requested)| AuthorizationInteractionScope {
                name,
                description,
                newly_requested,
            },
        )
        .collect();
    Ok(AuthorizationRequestRecord {
        id: authorization_request_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client,
        redirect_uri: RedirectUri::parse(
            row.try_get::<String, _>("redirect_uri")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        response_type: parse_response_type(
            &row.try_get::<String, _>("response_type")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        response_mode: parse_response_mode(
            &row.try_get::<String, _>("response_mode")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_state: row
            .try_get("client_state")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        requested_scopes,
        resource_uris: parse_resources(
            row.try_get("resource_uris")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        pkce_code_challenge: PkceChallenge::parse(
            row.try_get::<String, _>("pkce_code_challenge")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        nonce: row
            .try_get("nonce")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        prompt_values: parse_prompts(
            row.try_get("prompt_values")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        max_age_seconds: max_age
            .map(u64::try_from)
            .transpose()
            .map_err(|_| OAuthStoreError::CorruptData)?,
        expected_issuer: IssuerUri::parse(
            row.try_get::<String, _>("expected_issuer")
                .map_err(|_| OAuthStoreError::CorruptData)?,
            false,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        interaction_resource_name: row
            .try_get("interaction_resource_name")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        interaction_resource_description: row
            .try_get("interaction_resource_description")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        interaction_minimum_assurance: parse_assurance(
            &row.try_get::<String, _>("interaction_minimum_assurance")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        interaction_scopes,
        interaction_requirement: AuthorizationInteractionRequirement::from_db(
            &row.try_get::<String, _>("interaction_requirement")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        status: AuthorizationRequestStatus::from_db(
            &row.try_get::<String, _>("status")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        completed_at: row
            .try_get("completed_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn subject_from_row(row: &PgRow) -> Result<OAuthSubject, OAuthStoreError> {
    Ok(OAuthSubject {
        id: oauth_subject_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        user_id: subject_id(
            row.try_get("user_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        public_subject: PublicSubject::parse(
            row.try_get::<String, _>("public_subject")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn live_grant_from_row(row: &PgRow) -> Result<LiveGrant, OAuthStoreError> {
    Ok(LiveGrant {
        id: grant_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        public_subject: PublicSubject::parse(
            row.try_get::<String, _>("public_subject")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        user_id: subject_id(
            row.try_get("user_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        tenant_id: row
            .try_get::<Option<Uuid>, _>("tenant_id")
            .map_err(|_| OAuthStoreError::CorruptData)?
            .map(tenant_id)
            .transpose()?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        resources: parse_resources(
            row.try_get("resources")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        granted_scopes: parse_scopes(
            row.try_get("granted_scopes")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        authenticated_at: row
            .try_get("authenticated_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        assurance_level: parse_assurance(
            &row.try_get::<String, _>("assurance_level")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        authentication_methods: parse_auth_methods(
            row.try_get("authentication_methods")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        consented_at: row
            .try_get("consented_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        version: row
            .try_get("version")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn connected_grant_from_row(row: &PgRow) -> Result<ConnectedGrant, OAuthStoreError> {
    Ok(ConnectedGrant {
        grant_id: grant_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        client_name: row
            .try_get("display_name")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_uri: row
            .try_get("client_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        logo_uri: row
            .try_get("logo_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        tenant_id: row
            .try_get::<Option<Uuid>, _>("tenant_id")
            .map_err(|_| OAuthStoreError::CorruptData)?
            .map(tenant_id)
            .transpose()?,
        resources: parse_resources(
            row.try_get("resources")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        granted_scopes: parse_scopes(
            row.try_get("granted_scopes")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        consented_at: row
            .try_get("consented_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn validate_client_upsert(input: &ClientUpsert) -> Result<(), OAuthStoreError> {
    if !valid_trimmed_text(&input.display_name, MAX_DISPLAY_NAME_BYTES)
        || input.redirect_uris.is_empty()
        || input.redirect_uris.len() > 32
        || input.post_logout_redirect_uris.len() > 16
        || input.response_types != [ResponseType::Code]
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    validate_https_optional(input.client_uri.as_deref())?;
    validate_https_optional(input.logo_uri.as_deref())?;
    let response_types = response_type_values(&input.response_types);
    if !canonical_strings(&response_types, 1) {
        return Err(OAuthStoreError::InvalidInput);
    }
    let grant_types = grant_type_values(&input.grant_types);
    if !canonical_strings(&grant_types, 2)
        || !grant_types
            .iter()
            .any(|value| value == "authorization_code")
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    if !canonical_redirects(&input.redirect_uris)
        || !canonical_redirects(&input.post_logout_redirect_uris)
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    scope_values(&input.allowed_scopes)?;
    match input.token_endpoint_auth_method {
        TokenEndpointAuthMethod::None if input.client_secret_digest.is_none() => {}
        TokenEndpointAuthMethod::ClientSecretBasic if input.client_secret_digest.is_some() => {}
        TokenEndpointAuthMethod::PrivateKeyJwt
            if input.client_secret_digest.is_none() && input.public_jwks.is_some() => {}
        _ => return Err(OAuthStoreError::InvalidInput),
    }
    match input.source {
        ClientSource::ClientIdMetadata
            if input.metadata_document_uri.as_deref() == Some(input.client_id.as_str()) => {}
        ClientSource::ClientIdMetadata => return Err(OAuthStoreError::InvalidInput),
        ClientSource::PreRegistered | ClientSource::Dynamic
            if input.metadata_document_uri.is_none() && input.metadata_cache.is_none() => {}
        ClientSource::PreRegistered | ClientSource::Dynamic => {
            return Err(OAuthStoreError::InvalidInput);
        }
    }
    if let Some(cache) = input.metadata_cache.as_ref() {
        if !cache.body.is_object() || cache.expires_at <= cache.cached_at {
            return Err(OAuthStoreError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_authorization_request(
    input: &AuthorizationRequestCreate,
) -> Result<(), OAuthStoreError> {
    if input.expires_at <= input.created_at
        || input.expires_at > input.created_at + Duration::minutes(15)
        || input.client_state.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_STATE_BYTES || value.chars().any(char::is_control)
        })
        || input
            .nonce
            .as_ref()
            .is_some_and(|value| !valid_visible_text(value, MAX_NONCE_BYTES))
        || input
            .max_age_seconds
            .is_some_and(|value| value > 31_536_000)
        || !valid_trimmed_text(&input.interaction_resource_name, MAX_RESOURCE_NAME_BYTES)
        || !valid_trimmed_text(
            &input.interaction_resource_description,
            MAX_RESOURCE_DESCRIPTION_BYTES,
        )
        || input.interaction_scopes.len() != input.requested_scopes.len()
        || input
            .interaction_scopes
            .iter()
            .zip(&input.requested_scopes)
            .any(|(interaction, requested)| {
                &interaction.name != requested
                    || !valid_trimmed_text(&interaction.description, MAX_SCOPE_DESCRIPTION_BYTES)
            })
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    scope_values(&input.requested_scopes)?;
    resource_values(&input.resource_uris)?;
    prompt_values(&input.prompt_values)?;
    Ok(())
}

fn validate_grant_create(input: &GrantCreate) -> Result<(), OAuthStoreError> {
    if input.authenticated_at > input.consented_at
        || input.authentication_methods.is_empty()
        || input.authentication_methods.len() > MAX_AUTH_METHODS
        || input.granted_scopes.is_empty()
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    resource_values(&input.resources)?;
    scope_values(&input.granted_scopes)?;
    auth_method_values(&input.authentication_methods)?;
    Ok(())
}

fn validate_authorization_code(input: &AuthorizationCodeCreate) -> Result<(), OAuthStoreError> {
    if input.expires_at <= input.issued_at
        || input.expires_at > input.issued_at + Duration::minutes(10)
        || input
            .nonce
            .as_ref()
            .is_some_and(|value| !valid_visible_text(value, MAX_NONCE_BYTES))
        || input.granted_scopes.is_empty()
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    resource_values(&input.resource_uris)?;
    scope_values(&input.granted_scopes)?;
    Ok(())
}

fn valid_trimmed_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value.chars().any(|character| !character.is_whitespace())
        && !value.chars().any(char::is_control)
}

fn valid_visible_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_https_optional(value: Option<&str>) -> Result<(), OAuthStoreError> {
    if value.is_some_and(|value| {
        value.len() < 8
            || value.len() > MAX_CLIENT_URI_BYTES
            || !value.starts_with("https://")
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
            || value.contains('"')
            || value.contains('\\')
    }) {
        Err(OAuthStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn canonical_redirects(values: &[RedirectUri]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_strings(values: &[String], maximum: usize) -> bool {
    !values.is_empty() && values.len() <= maximum && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_subset(candidate: &[String], allowed: &[String]) -> bool {
    candidate
        .iter()
        .all(|value| allowed.binary_search(value).is_ok())
}

fn resource_values(values: &[ResourceUri]) -> Result<Vec<String>, OAuthStoreError> {
    if values.len() > MAX_RESOURCES {
        return Err(OAuthStoreError::InvalidInput);
    }
    let result = values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

fn scope_values(values: &[Scope]) -> Result<Vec<String>, OAuthStoreError> {
    if values.len() > MAX_SCOPES {
        return Err(OAuthStoreError::InvalidInput);
    }
    let result = values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

fn redirect_values(values: &[RedirectUri]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect()
}

fn auth_method_values(values: &[AuthMethod]) -> Result<Vec<String>, OAuthStoreError> {
    if values.is_empty() || values.len() > MAX_AUTH_METHODS {
        return Err(OAuthStoreError::InvalidInput);
    }
    let result = values
        .iter()
        .copied()
        .map(auth_method_value)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

fn prompt_values(values: &[Prompt]) -> Result<Vec<String>, OAuthStoreError> {
    let result = values
        .iter()
        .copied()
        .map(prompt_value)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if result.len() > 3
        || result.windows(2).any(|pair| pair[0] >= pair[1])
        || result.iter().any(|value| value == "none") && result.len() != 1
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

fn response_type_values(values: &[ResponseType]) -> Vec<String> {
    values
        .iter()
        .copied()
        .map(response_type_value)
        .map(str::to_owned)
        .collect()
}

fn grant_type_values(values: &[GrantType]) -> Vec<String> {
    values
        .iter()
        .copied()
        .map(grant_type_value)
        .map(str::to_owned)
        .collect()
}

const fn application_type_value(value: ApplicationType) -> &'static str {
    match value {
        ApplicationType::Web => "web",
        ApplicationType::Native => "native",
    }
}

const fn token_auth_method_value(value: TokenEndpointAuthMethod) -> &'static str {
    match value {
        TokenEndpointAuthMethod::None => "none",
        TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
        TokenEndpointAuthMethod::PrivateKeyJwt => "private_key_jwt",
    }
}

const fn response_type_value(value: ResponseType) -> &'static str {
    match value {
        ResponseType::Code => "code",
    }
}

const fn response_mode_value(value: ResponseMode) -> &'static str {
    match value {
        ResponseMode::Query => "query",
    }
}

const fn grant_type_value(value: GrantType) -> &'static str {
    match value {
        GrantType::AuthorizationCode => "authorization_code",
        GrantType::RefreshToken => "refresh_token",
    }
}

const fn prompt_value(value: Prompt) -> &'static str {
    match value {
        Prompt::None => "none",
        Prompt::Login => "login",
        Prompt::Consent => "consent",
    }
}

const fn assurance_value(value: AssuranceLevel) -> &'static str {
    match value {
        AssuranceLevel::Aal1 => "aal1",
        AssuranceLevel::Aal2 => "aal2",
        AssuranceLevel::Aal3 => "aal3",
    }
}

const fn auth_method_value(value: AuthMethod) -> &'static str {
    match value {
        AuthMethod::Password => "password",
        AuthMethod::Session => "session",
        AuthMethod::Jwt => "jwt",
        AuthMethod::Oidc => "oidc",
        AuthMethod::ApiKey => "api_key",
        AuthMethod::WebAuthn => "web_authn",
        AuthMethod::Totp => "totp",
    }
}

fn parse_application_type(value: &str) -> Result<ApplicationType, OAuthStoreError> {
    match value {
        "web" => Ok(ApplicationType::Web),
        "native" => Ok(ApplicationType::Native),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_token_auth_method(value: &str) -> Result<TokenEndpointAuthMethod, OAuthStoreError> {
    match value {
        "none" => Ok(TokenEndpointAuthMethod::None),
        "client_secret_basic" => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
        "private_key_jwt" => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_response_type(value: &str) -> Result<ResponseType, OAuthStoreError> {
    match value {
        "code" => Ok(ResponseType::Code),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_response_mode(value: &str) -> Result<ResponseMode, OAuthStoreError> {
    match value {
        "query" => Ok(ResponseMode::Query),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_grant_type(value: &str) -> Result<GrantType, OAuthStoreError> {
    match value {
        "authorization_code" => Ok(GrantType::AuthorizationCode),
        "refresh_token" => Ok(GrantType::RefreshToken),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_assurance(value: &str) -> Result<AssuranceLevel, OAuthStoreError> {
    match value {
        "aal1" => Ok(AssuranceLevel::Aal1),
        "aal2" => Ok(AssuranceLevel::Aal2),
        "aal3" => Ok(AssuranceLevel::Aal3),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_auth_methods(values: Vec<String>) -> Result<Vec<AuthMethod>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "password" => Ok(AuthMethod::Password),
            "session" => Ok(AuthMethod::Session),
            "jwt" => Ok(AuthMethod::Jwt),
            "oidc" => Ok(AuthMethod::Oidc),
            "api_key" => Ok(AuthMethod::ApiKey),
            "web_authn" => Ok(AuthMethod::WebAuthn),
            "totp" => Ok(AuthMethod::Totp),
            _ => Err(OAuthStoreError::CorruptData),
        })
        .collect()
}

fn parse_prompts(values: Vec<String>) -> Result<Vec<Prompt>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "none" => Ok(Prompt::None),
            "login" => Ok(Prompt::Login),
            "consent" => Ok(Prompt::Consent),
            _ => Err(OAuthStoreError::CorruptData),
        })
        .collect()
}

fn parse_resources(values: Vec<String>) -> Result<Vec<ResourceUri>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| ResourceUri::parse(value, false).map_err(|_| OAuthStoreError::CorruptData))
        .collect()
}

fn parse_scopes(values: Vec<String>) -> Result<Vec<Scope>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| Scope::new(value).map_err(|_| OAuthStoreError::CorruptData))
        .collect()
}

fn digest_from_vec(value: Vec<u8>) -> Result<BearerDigest, OAuthStoreError> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| OAuthStoreError::CorruptData)?;
    Ok(BearerDigest::from_bytes(bytes))
}

fn valid_uuid_v7(value: Uuid) -> Result<(), OAuthStoreError> {
    if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122 {
        Ok(())
    } else {
        Err(OAuthStoreError::CorruptData)
    }
}

fn oauth_client_id(value: Uuid) -> Result<OAuthClientRecordId, OAuthStoreError> {
    OAuthClientRecordId::from_uuid(value)
}

fn authorization_request_id(value: Uuid) -> Result<AuthorizationRequestId, OAuthStoreError> {
    AuthorizationRequestId::from_uuid(value)
}

fn oauth_subject_id(value: Uuid) -> Result<OAuthSubjectId, OAuthStoreError> {
    OAuthSubjectId::from_uuid(value)
}

fn refresh_family_id(value: Uuid) -> Result<RefreshFamilyId, OAuthStoreError> {
    RefreshFamilyId::from_uuid(value)
}

fn refresh_token_id(value: Uuid) -> Result<RefreshTokenId, OAuthStoreError> {
    RefreshTokenId::from_uuid(value)
}

fn grant_id(value: Uuid) -> Result<GrantId, OAuthStoreError> {
    GrantId::from_uuid(value).map_err(|_| OAuthStoreError::CorruptData)
}

fn subject_id(value: Uuid) -> Result<SubjectId, OAuthStoreError> {
    SubjectId::from_uuid(value).map_err(|_| OAuthStoreError::CorruptData)
}

fn tenant_id(value: Uuid) -> Result<TenantId, OAuthStoreError> {
    TenantId::from_uuid(value).map_err(|_| OAuthStoreError::CorruptData)
}

async fn finish<T>(
    transaction: Transaction<'_, Postgres>,
    result: Result<T, OAuthStoreError>,
) -> Result<T, OAuthStoreError> {
    match result {
        Ok(value) => {
            transaction.commit().await.map_err(|error| map_db(&error))?;
            Ok(value)
        }
        Err(error) => {
            transaction
                .rollback()
                .await
                .map_err(|rollback| map_db(&rollback))?;
            Err(error)
        }
    }
}

fn map_db(error: &sqlx::Error) -> OAuthStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return OAuthStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23503" | "23505") => OAuthStoreError::Conflict,
        Some(code) if matches!(code.as_ref(), "23502" | "23514" | "22001") => {
            OAuthStoreError::InvalidInput
        }
        _ => OAuthStoreError::Unavailable,
    }
}
