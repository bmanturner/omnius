//! Enterprise-managed MCP authorization using bounded ID-JAG delegation evidence.
//!
//! The cryptographic verifier, replay store, durable identity-link store, tenant
//! entitlement store, ordinary authorization policy, consent policy, and audit
//! transaction are explicit ports. A verified enterprise assertion produces one
//! canonical user [`Principal`] plus a separate immutable delegation chain. Asserted
//! client, model, tool, and scope claims never authorize an invocation by themselves.

use std::{fmt, future::Future};

use omnius_agent_capability_registry::{
    CapabilityDocument, CapabilityKey, ConfirmationPolicy, Exposure,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_auth_oauth_server::{
    AccessTokenClaims, AccessTokenClaimsInput, ClientId, GrantId, IssuerUri, JwtId, ResourceUri,
    store::PublicSubject,
};
use omnius_core::RequestId;
use omnius_mcp_auth_client_credentials::{
    OAuthClientAuthenticationMethod, ResourceAuthorizationPolicy, ResourceIssuerPort,
};
use omnius_mcp_auth_oauth::{
    CapabilityVisibility, McpAuthenticatedIdentity, McpOperation, McpOperationAuthorizer,
    OperationGuard, TenantGuard,
};
use omnius_mcp_server_core::McpRequestContext;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Per-request capability identifier for enterprise-managed authorization.
pub const ENTERPRISE_AUTHORIZATION_EXTENSION_ID: &str =
    "io.modelcontextprotocol/enterprise-managed-authorization";
/// Exact revision implemented by enterprise-managed authorization.
pub const ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION: &str = "2026-07-28";
/// Authorization-server discovery profile advertised only when enterprise ports are live.
pub const ID_JAG_AUTHORIZATION_GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
/// RFC 7523 JWT bearer grant used to present an ID-JAG to the resource AS.
pub const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// RFC token type identifying an ID-JAG.
pub const ID_JAG_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// Required JOSE `typ` for an ID-JAG.
pub const ID_JAG_JOSE_TYPE: &str = "oauth-id-jag+jwt";
/// OAuth token type of the resource AS output.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

const MAX_COMPACT_TOKEN_BYTES: usize = 16 * 1024;
const MAX_VISIBLE_CATALOG_CAPABILITIES: usize = 4_096;
const MAX_EXTERNAL_SUBJECT_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_LINK_ID_BYTES: usize = 128;
const MAX_CAPABILITY_ID_BYTES: usize = 256;
const MAX_CORRELATION_ID_BYTES: usize = 128;
const MAX_SCOPES: usize = 128;
const MAX_LINK_CLIENTS: usize = 32;
const MAX_LINK_RESOURCES: usize = 32;
const MAX_REDACTED_ARGUMENT_SUMMARY_BYTES: usize = 16 * 1024;
const MAX_CONFIGURED_LIFETIME: Duration = Duration::minutes(15);

fn validate_bounded(value: &str, max_bytes: usize) -> Result<(), EnterpriseIdentifierError> {
    if value.is_empty() {
        return Err(EnterpriseIdentifierError::Empty);
    }
    if value.len() > max_bytes {
        return Err(EnterpriseIdentifierError::TooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(EnterpriseIdentifierError::InvalidCharacter);
    }
    Ok(())
}

/// Failure to construct a bounded enterprise identifier.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnterpriseIdentifierError {
    /// The identifier was empty.
    #[error("enterprise identifier must not be empty")]
    Empty,
    /// The identifier exceeded its bound.
    #[error("enterprise identifier exceeds its size limit")]
    TooLong,
    /// The identifier contained a control character.
    #[error("enterprise identifier contains a forbidden character")]
    InvalidCharacter,
}

macro_rules! bounded_identifier {
    ($name:ident, $max:ident, $description:literal, $redacted:expr) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns the bounded identifier.
            ///
            /// # Errors
            ///
            /// Returns [`EnterpriseIdentifierError`] when empty, oversized, or
            /// control-character-bearing.
            pub fn new(value: impl Into<String>) -> Result<Self, EnterpriseIdentifierError> {
                let value = value.into();
                validate_bounded(&value, $max)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                if $redacted {
                    formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
                } else {
                    formatter
                        .debug_tuple(stringify!($name))
                        .field(&self.as_str())
                        .finish()
                }
            }
        }
    };
}

bounded_identifier!(
    ExternalSubjectId,
    MAX_EXTERNAL_SUBJECT_BYTES,
    "Stable issuer-scoped external subject. It is never an email-based link key.",
    true
);
bounded_identifier!(
    KeyId,
    MAX_KEY_ID_BYTES,
    "Bounded JOSE key identifier.",
    false
);
bounded_identifier!(
    IdentityLinkId,
    MAX_LINK_ID_BYTES,
    "Durable enterprise identity-link identifier.",
    false
);
bounded_identifier!(
    CapabilityId,
    MAX_CAPABILITY_ID_BYTES,
    "Bounded MCP capability identifier used by ordinary authorization.",
    false
);
bounded_identifier!(
    AuditCorrelationId,
    MAX_CORRELATION_ID_BYTES,
    "Bounded request or trace correlation identifier.",
    false
);
bounded_identifier!(
    AssertionJwtId,
    MAX_CORRELATION_ID_BYTES,
    "ID-JAG assertion JWT identifier.",
    true
);

/// Compact ID-JAG input retained only long enough for cryptographic verification.
pub struct CompactIdJag(Box<str>);

impl CompactIdJag {
    /// Binds the compact assertion to a 16 KiB input ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`EnterpriseIdentifierError`] when empty, oversized, or control-bearing.
    pub fn new(value: impl Into<String>) -> Result<Self, EnterpriseIdentifierError> {
        let value = value.into();
        validate_bounded(&value, MAX_COMPACT_TOKEN_BYTES)?;
        Ok(Self(value.into_boxed_str()))
    }

    /// Borrows the compact token for the signature verifier only.
    #[must_use]
    pub fn expose_to_verifier(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CompactIdJag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompactIdJag(<redacted>)")
    }
}

/// Proof that the resource AS received the exact RFC 7523 JWT bearer grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdJagJwtBearerGrant(());

impl IdJagJwtBearerGrant {
    /// Validates the exact OAuth grant type.
    ///
    /// # Errors
    ///
    /// Returns [`EnterpriseAuthorizationError::UnsupportedGrant`] for every other
    /// grant, including local access-token exchange.
    pub fn new(grant_type: &str) -> Result<Self, EnterpriseAuthorizationError> {
        (grant_type == JWT_BEARER_GRANT_TYPE)
            .then_some(Self(()))
            .ok_or(EnterpriseAuthorizationError::UnsupportedGrant)
    }
}

/// JOSE signature algorithms understood by the signature-verifier boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignatureAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using P-384 and SHA-384.
    Es384,
    /// Edwards-curve `EdDSA`.
    EdDsa,
    /// RSA PKCS#1 v1.5 with SHA-256.
    Rs256,
    /// RSA-PSS with SHA-256.
    Ps256,
    /// Symmetric HMAC, represented so policy can explicitly reject it.
    Hs256,
    /// An algorithm unknown to this profile.
    Other,
}

/// Typed protected header returned only after cryptographic signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdJagProtectedHeader {
    /// JOSE `typ`; it must equal [`ID_JAG_JOSE_TYPE`].
    pub token_type: Option<String>,
    /// JOSE signature algorithm.
    pub algorithm: Option<SignatureAlgorithm>,
    /// JOSE key identifier used by the trusted issuer key set.
    pub key_id: Option<KeyId>,
}

/// Typed ID-JAG payload returned only after cryptographic signature verification.
///
/// Optional fields retain claim-presence information so the resource AS can reject every
/// missing registered or profile-specific claim without using untyped maps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdJagPayload {
    /// Enterprise `IdP` issuer.
    pub issuer: Option<IssuerUri>,
    /// Stable issuer-scoped user subject.
    pub subject: Option<ExternalSubjectId>,
    /// Audiences; the valid profile has exactly the resource AS issuer.
    pub audiences: Option<Vec<IssuerUri>>,
    /// Exact MCP protected resource.
    pub resource: Option<ResourceUri>,
    /// MCP OAuth client delegated by the enterprise `IdP`.
    pub client_id: Option<ClientId>,
    /// Assertion replay identifier, separate from locally issued OAuth token identifiers.
    pub jwt_id: Option<AssertionJwtId>,
    /// Assertion issuance time.
    pub issued_at: Option<OffsetDateTime>,
    /// Optional assertion not-before time.
    pub not_before: Option<OffsetDateTime>,
    /// Assertion expiration time.
    pub expires_at: Option<OffsetDateTime>,
    /// Enterprise-delegated scope ceiling.
    pub scopes: Option<Vec<Scope>>,
}

/// Signature-verified typed ID-JAG document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureVerifiedIdJag {
    header: IdJagProtectedHeader,
    payload: IdJagPayload,
}

impl SignatureVerifiedIdJag {
    /// Creates the output value implemented by a cryptographic verifier adapter.
    ///
    /// This constructor does not itself verify a signature; callers cannot submit this
    /// value to the exchange service. The service obtains it exclusively through
    /// [`IdJagSignatureVerifier`].
    #[must_use]
    pub fn new(header: IdJagProtectedHeader, payload: IdJagPayload) -> Self {
        Self { header, payload }
    }
}

/// Value-free cryptographic ID-JAG verifier denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdJagVerificationError {
    /// The compact JWT or typed claim shape was malformed or exceeded a bound.
    #[error("ID-JAG is malformed")]
    Malformed,
    /// No configured trust relationship exists for the unverified issuer hint.
    #[error("ID-JAG issuer is not trusted")]
    UntrustedIssuer,
    /// Trusted issuer key resolution failed closed.
    #[error("ID-JAG signing key is unavailable")]
    KeyUnavailable,
    /// The referenced key identifier is unknown for the configured issuer.
    #[error("ID-JAG signing key is unknown")]
    UnknownKey,
    /// Cryptographic signature validation failed.
    #[error("ID-JAG signature is invalid")]
    InvalidSignature,
}

/// Cryptographic verification port for bounded ID-JAGs.
///
/// Implementations must parse with duplicate-key rejection, use `trusted_issuers` only
/// as preconfigured key sources (never arbitrary assertion-controlled JWKS URLs), bind
/// `kid` to that issuer, verify the signature over the compact input, and return no raw
/// token, email, or unknown claim map.
pub trait IdJagSignatureVerifier: Send + Sync {
    /// Verifies and decodes a bounded ID-JAG.
    fn verify_signature(
        &self,
        token: &CompactIdJag,
        trusted_issuers: &[IssuerUri],
    ) -> impl Future<Output = Result<SignatureVerifiedIdJag, IdJagVerificationError>> + Send;
}

/// Atomic assertion replay result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    /// The `(issuer, assertion jti)` pair was atomically stored through the skew horizon.
    Fresh,
    /// The `(issuer, jti)` pair was already consumed.
    Replayed,
}

/// Value-free replay-store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise assertion replay state is unavailable")]
pub struct ReplayStoreError;

/// Durable, atomic ID-JAG replay boundary.
pub trait IdJagReplayPort: Send + Sync {
    /// Consumes one issuer-scoped assertion JTI exactly once through `retain_until`.
    fn consume_once(
        &self,
        issuer: &IssuerUri,
        jwt_id: &AssertionJwtId,
        retain_until: OffsetDateTime,
    ) -> impl Future<Output = Result<ReplayDecision, ReplayStoreError>> + Send;
}

/// Constructor parameters for one durable enterprise identity link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseIdentityLinkInput {
    /// Durable row identifier.
    pub link_id: IdentityLinkId,
    /// Exact enterprise issuer.
    pub issuer: IssuerUri,
    /// Stable external subject; never an email address.
    pub external_subject: ExternalSubjectId,
    /// Canonical effective user.
    pub local_subject: SubjectId,
    /// Tenant chosen by the durable link, never by the MCP client.
    pub tenant_id: TenantId,
    /// Canonical durable OAuth grant installed in live access-token state.
    pub grant_id: GrantId,
    /// Opaque issuer-public subject installed in live access-token state.
    pub public_subject: PublicSubject,
    /// Link live-state flag.
    pub active: bool,
    /// Issuer-local clients permitted by this link.
    pub permitted_clients: Vec<ClientId>,
    /// MCP resources permitted by this link.
    pub permitted_resources: Vec<ResourceUri>,
    /// Link policy scope ceiling.
    pub allowed_scopes: Vec<Scope>,
    /// Monotonic identity-link version.
    pub link_version: u64,
    /// Monotonic link revocation version.
    pub revocation_version: u64,
    /// Monotonic enterprise authorization-policy version.
    pub policy_version: u64,
}

/// One authoritative enterprise identity link snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseIdentityLink {
    link_id: IdentityLinkId,
    issuer: IssuerUri,
    external_subject: ExternalSubjectId,
    local_subject: SubjectId,
    tenant_id: TenantId,
    grant_id: GrantId,
    public_subject: PublicSubject,
    active: bool,
    permitted_clients: Vec<ClientId>,
    permitted_resources: Vec<ResourceUri>,
    allowed_scopes: Vec<Scope>,
    link_version: u64,
    revocation_version: u64,
    policy_version: u64,
}

impl EnterpriseIdentityLink {
    /// Builds a bounded authoritative identity link.
    ///
    /// # Errors
    ///
    /// Returns [`EnterpriseAuthorizationError::InvalidAuthoritativeState`] for empty,
    /// oversized, duplicate-free-empty, or zero-version policy state.
    pub fn new(input: EnterpriseIdentityLinkInput) -> Result<Self, EnterpriseAuthorizationError> {
        let permitted_clients = canonical_values(input.permitted_clients, MAX_LINK_CLIENTS)?;
        let permitted_resources = canonical_values(input.permitted_resources, MAX_LINK_RESOURCES)?;
        let allowed_scopes = canonical_scopes(input.allowed_scopes)?;
        if permitted_clients.is_empty()
            || permitted_resources.is_empty()
            || allowed_scopes.is_empty()
            || input.link_version == 0
            || input.revocation_version == 0
            || input.policy_version == 0
        {
            return Err(EnterpriseAuthorizationError::InvalidAuthoritativeState);
        }
        Ok(Self {
            link_id: input.link_id,
            issuer: input.issuer,
            external_subject: input.external_subject,
            local_subject: input.local_subject,
            tenant_id: input.tenant_id,
            grant_id: input.grant_id,
            public_subject: input.public_subject,
            active: input.active,
            permitted_clients,
            permitted_resources,
            allowed_scopes,
            link_version: input.link_version,
            revocation_version: input.revocation_version,
            policy_version: input.policy_version,
        })
    }
}

/// Value-free identity-link store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise identity link is unavailable")]
pub struct IdentityLinkStoreError;

/// Durable identity-link boundary keyed only by exact issuer and stable subject.
pub trait EnterpriseIdentityLinkPort: Send + Sync {
    /// Loads a live link candidate without using email or client-selected tenant data.
    fn load_live_link(
        &self,
        issuer: &IssuerUri,
        external_subject: &ExternalSubjectId,
    ) -> impl Future<Output = Result<EnterpriseIdentityLink, IdentityLinkStoreError>> + Send;
}

/// Constructor parameters for an authoritative tenant entitlement snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantEntitlementInput {
    /// Canonical effective user.
    pub local_subject: SubjectId,
    /// Tenant from the durable identity link.
    pub tenant_id: TenantId,
    /// Whether membership and enterprise entitlement remain live.
    pub active: bool,
    /// Current tenant authorization scope ceiling.
    pub allowed_scopes: Vec<Scope>,
    /// Monotonic tenant authorization revision.
    pub authorization_revision: u64,
}

/// One authoritative live tenant entitlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantEntitlement {
    local_subject: SubjectId,
    tenant_id: TenantId,
    active: bool,
    allowed_scopes: Vec<Scope>,
    authorization_revision: u64,
}

impl TenantEntitlement {
    /// Builds a bounded tenant-entitlement snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`EnterpriseAuthorizationError::InvalidAuthoritativeState`] for an
    /// empty/oversized scope ceiling or zero revision.
    pub fn new(input: TenantEntitlementInput) -> Result<Self, EnterpriseAuthorizationError> {
        let allowed_scopes = canonical_scopes(input.allowed_scopes)?;
        if allowed_scopes.is_empty() || input.authorization_revision == 0 {
            return Err(EnterpriseAuthorizationError::InvalidAuthoritativeState);
        }
        Ok(Self {
            local_subject: input.local_subject,
            tenant_id: input.tenant_id,
            active: input.active,
            allowed_scopes,
            authorization_revision: input.authorization_revision,
        })
    }
}

/// Value-free tenant-entitlement store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise tenant entitlement is unavailable")]
pub struct TenantEntitlementStoreError;

/// Authoritative user/tenant membership and entitlement boundary.
pub trait TenantEntitlementPort: Send + Sync {
    /// Revalidates the user and tenant chosen by the durable identity link.
    fn load_live_entitlement(
        &self,
        local_subject: SubjectId,
        tenant_id: TenantId,
    ) -> impl Future<Output = Result<TenantEntitlement, TenantEntitlementStoreError>> + Send;
}

/// Fully validated ID-JAG claims retained without email or unknown claim maps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedIdJagClaims {
    /// Trusted enterprise issuer.
    pub issuer: IssuerUri,
    /// Stable issuer-scoped subject.
    pub subject: ExternalSubjectId,
    /// Exact resource AS audience.
    pub audience: IssuerUri,
    /// Exact MCP protected resource.
    pub resource: ResourceUri,
    /// Authenticated MCP OAuth client.
    pub client_id: ClientId,
    /// Assertion replay identifier, never reused as a local access-token JTI.
    pub jwt_id: AssertionJwtId,
    /// Issuance time.
    pub issued_at: OffsetDateTime,
    /// Optional not-before time.
    pub not_before: Option<OffsetDateTime>,
    /// Expiration time.
    pub expires_at: OffsetDateTime,
    /// Enterprise-delegated scope ceiling.
    pub scopes: Vec<Scope>,
}

/// Configuration for semantic ID-JAG validation and local token issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseAuthorizationConfig {
    trusted_issuers: Vec<IssuerUri>,
    allowed_algorithms: Vec<SignatureAlgorithm>,
    id_jag_max_lifetime: Duration,
    clock_skew: Duration,
    access_token_lifetime: Duration,
}

/// Invalid enterprise authorization configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnterpriseConfigError {
    /// At least one enterprise issuer is required.
    #[error("enterprise trusted issuer set is empty")]
    EmptyTrustedIssuers,
    /// At least one asymmetric signature algorithm is required.
    #[error("enterprise signature algorithm set is invalid")]
    InvalidAlgorithms,
    /// ID-JAG or access-token lifetime is non-positive or exceeds 15 minutes.
    #[error("enterprise token lifetime is invalid")]
    InvalidLifetime,
    /// Clock skew was negative or exceeded two minutes.
    #[error("enterprise clock skew is invalid")]
    InvalidClockSkew,
}

impl EnterpriseAuthorizationConfig {
    /// Creates strict enterprise ID-JAG and local-token validation policy.
    ///
    /// # Errors
    ///
    /// Returns [`EnterpriseConfigError`] for empty trust, symmetric/unknown algorithm
    /// policy, non-short lifetimes, or excessive clock skew.
    pub fn new(
        mut trusted_issuers: Vec<IssuerUri>,
        mut allowed_algorithms: Vec<SignatureAlgorithm>,
        id_jag_max_lifetime: Duration,
        clock_skew: Duration,
        access_token_lifetime: Duration,
    ) -> Result<Self, EnterpriseConfigError> {
        trusted_issuers.sort_unstable();
        trusted_issuers.dedup();
        allowed_algorithms.sort_unstable_by_key(|algorithm| *algorithm as u8);
        allowed_algorithms.dedup();
        if trusted_issuers.is_empty() {
            return Err(EnterpriseConfigError::EmptyTrustedIssuers);
        }
        if allowed_algorithms.is_empty()
            || allowed_algorithms.iter().any(|algorithm| {
                matches!(
                    algorithm,
                    SignatureAlgorithm::Hs256 | SignatureAlgorithm::Other
                )
            })
        {
            return Err(EnterpriseConfigError::InvalidAlgorithms);
        }
        if id_jag_max_lifetime < Duration::SECOND
            || id_jag_max_lifetime > MAX_CONFIGURED_LIFETIME
            || access_token_lifetime < Duration::SECOND
            || access_token_lifetime > MAX_CONFIGURED_LIFETIME
        {
            return Err(EnterpriseConfigError::InvalidLifetime);
        }
        if clock_skew < Duration::ZERO || clock_skew > Duration::minutes(2) {
            return Err(EnterpriseConfigError::InvalidClockSkew);
        }
        Ok(Self {
            trusted_issuers,
            allowed_algorithms,
            id_jag_max_lifetime,
            clock_skew,
            access_token_lifetime,
        })
    }

    /// Returns trusted issuers suitable for authorization-server discovery wiring.
    #[must_use]
    pub fn trusted_issuers(&self) -> &[IssuerUri] {
        &self.trusted_issuers
    }
}

/// Authenticated, live OAuth client state returned by the resource authorization server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseOAuthClientState {
    /// Issuer that authenticated and registered the client.
    pub issuer: IssuerUri,
    /// Issuer-local client identifier.
    pub client_id: ClientId,
    /// Exact protected resource authorized for this client.
    pub resource: ResourceUri,
    /// Current client scope ceiling.
    pub allowed_scopes: Vec<Scope>,
    /// Current nonzero client authorization revision.
    pub authorization_revision: u64,
    /// Authentication mechanism accepted by the authorization server.
    pub authentication_method: OAuthClientAuthenticationMethod,
    /// Whether the client and its resource binding remain enabled.
    pub active: bool,
}

/// Value-free enterprise OAuth client authentication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise OAuth client authentication failed")]
pub struct EnterpriseOAuthClientError;

/// Resource-AS boundary that authenticates a client and atomically reloads its live registration.
pub trait EnterpriseOAuthClientPort: Send + Sync {
    /// Authentication input owned by the authorization-server adapter.
    type Authentication: ?Sized + Sync;

    /// Authenticates the request and returns current issuer-local registration state.
    fn authenticate_client(
        &self,
        authentication: &Self::Authentication,
        resource: &ResourceUri,
    ) -> impl Future<Output = Result<EnterpriseOAuthClientState, EnterpriseOAuthClientError>> + Send;
}

/// Exact JWT bearer exchange request presented to the resource authorization server.
#[derive(Debug)]
pub struct EnterpriseExchangeRequest {
    /// Complete canonical request context used for exact extension negotiation.
    pub request_context: McpRequestContext,
    /// Exact RFC 7523 grant proof.
    pub grant: IdJagJwtBearerGrant,
    /// Compact assertion, redacted in `Debug` and never copied to evidence.
    pub assertion: CompactIdJag,
    /// Exact MCP resource indicator requested from the resource AS.
    pub resource: ResourceUri,
    /// Requested local access-token scopes.
    pub requested_scopes: Vec<Scope>,
}

/// Immutable SHA-256 fingerprint used instead of raw assertion or external subject data.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct EvidenceFingerprint([u8; 32]);

impl EvidenceFingerprint {
    fn from_domain_value(domain: &[u8], value: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([0]);
        hasher.update(value.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Returns the fixed-size fingerprint for equality/correlation without exposing input.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EvidenceFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceFingerprint(<sha256>)")
    }
}

/// Separate immutable enterprise delegation chain evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegationChainEvidence {
    enterprise_issuer: IssuerUri,
    external_subject_fingerprint: EvidenceFingerprint,
    mcp_client_id: ClientId,
    resource: ResourceUri,
    assertion_fingerprint: EvidenceFingerprint,
    identity_link_id: IdentityLinkId,
    effective_subject: SubjectId,
    tenant_id: TenantId,
    link_version: u64,
    revocation_version: u64,
    policy_version: u64,
    tenant_authorization_revision: u64,
}

impl DelegationChainEvidence {
    /// Returns the enterprise issuer at the head of the chain.
    #[must_use]
    pub fn enterprise_issuer(&self) -> &IssuerUri {
        &self.enterprise_issuer
    }

    /// Returns the MCP OAuth client delegated by the enterprise issuer.
    #[must_use]
    pub fn mcp_client_id(&self) -> &ClientId {
        &self.mcp_client_id
    }

    /// Returns the exact MCP resource at the tail of the chain.
    #[must_use]
    pub fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// Returns the canonical effective user.
    #[must_use]
    pub const fn effective_subject(&self) -> SubjectId {
        self.effective_subject
    }

    /// Returns the tenant selected by the durable identity link.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the durable identity-link identifier.
    #[must_use]
    pub fn identity_link_id(&self) -> &IdentityLinkId {
        &self.identity_link_id
    }

    /// Returns the link version captured during exchange.
    #[must_use]
    pub const fn link_version(&self) -> u64 {
        self.link_version
    }

    /// Returns the revocation version captured during exchange.
    #[must_use]
    pub const fn revocation_version(&self) -> u64 {
        self.revocation_version
    }

    /// Returns the enterprise policy version captured during exchange.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Returns the tenant authorization revision captured during exchange.
    #[must_use]
    pub const fn tenant_authorization_revision(&self) -> u64 {
        self.tenant_authorization_revision
    }

    /// Returns the assertion fingerprint, never the assertion JTI or raw JWT.
    #[must_use]
    pub const fn assertion_fingerprint(&self) -> EvidenceFingerprint {
        self.assertion_fingerprint
    }
}

impl fmt::Debug for DelegationChainEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegationChainEvidence")
            .field("enterprise_issuer", &self.enterprise_issuer)
            .field(
                "external_subject_fingerprint",
                &self.external_subject_fingerprint,
            )
            .field("mcp_client_id", &self.mcp_client_id)
            .field("resource", &self.resource)
            .field("assertion_fingerprint", &self.assertion_fingerprint)
            .field("identity_link_id", &self.identity_link_id)
            .field("effective_subject", &self.effective_subject)
            .field("tenant_id", &self.tenant_id)
            .field("link_version", &self.link_version)
            .field("revocation_version", &self.revocation_version)
            .field("policy_version", &self.policy_version)
            .field(
                "tenant_authorization_revision",
                &self.tenant_authorization_revision,
            )
            .finish()
    }
}

/// Successful enterprise exchange output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseExchange {
    /// Canonical effective user for ordinary authorization.
    pub principal: Principal,
    /// Canonical opaque OAuth access-token claims to sign.
    pub access_token_claims: AccessTokenClaims,
    /// Separate immutable delegation evidence.
    pub delegation: DelegationChainEvidence,
}

impl EnterpriseExchange {
    /// Returns the exact issued OAuth token type.
    #[must_use]
    pub const fn issued_token_type(&self) -> &'static str {
        ACCESS_TOKEN_TYPE
    }

    /// Enterprise JWT bearer exchange never returns a refresh token.
    #[must_use]
    pub const fn refresh_token_issued(&self) -> bool {
        false
    }
}

/// Redacted enterprise exchange denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnterpriseAuthorizationError {
    /// Enterprise authorization is default-disabled and was not negotiated.
    #[error("MCP enterprise authorization extension is not negotiated")]
    ExtensionNotNegotiated,
    /// The AS token request was not the exact JWT bearer grant.
    #[error("OAuth grant is not the enterprise ID-JAG JWT bearer grant")]
    UnsupportedGrant,
    /// OAuth client authentication or live registration revalidation failed.
    #[error("enterprise OAuth client is unavailable")]
    OAuthClientUnavailable,
    /// Cryptographic verification failed without exposing token details.
    #[error(transparent)]
    VerificationFailed(IdJagVerificationError),
    /// JOSE `typ` was absent.
    #[error("ID-JAG typ is missing")]
    MissingType,
    /// JOSE `typ` did not match the ID-JAG profile.
    #[error("ID-JAG typ is invalid")]
    InvalidType,
    /// JOSE `alg` was absent.
    #[error("ID-JAG alg is missing")]
    MissingAlgorithm,
    /// JOSE `alg` was not explicitly allowed.
    #[error("ID-JAG alg is not allowed")]
    DisallowedAlgorithm,
    /// JOSE `kid` was absent.
    #[error("ID-JAG kid is missing")]
    MissingKeyId,
    /// The `iss` claim was absent.
    #[error("ID-JAG issuer is missing")]
    MissingIssuer,
    /// The `iss` claim is not configured as an enterprise issuer.
    #[error("ID-JAG issuer is not trusted")]
    UntrustedIssuer,
    /// A locally issued resource access token was presented as an enterprise assertion.
    #[error("locally issued access tokens cannot be exchanged as ID-JAGs")]
    LocalTokenExchangeDenied,
    /// The `aud` claim was absent.
    #[error("ID-JAG audience is missing")]
    MissingAudience,
    /// The audience was not exactly the resource AS issuer.
    #[error("ID-JAG audience does not match resource authorization server")]
    AudienceMismatch,
    /// The `resource` claim was absent.
    #[error("ID-JAG resource is missing")]
    MissingResource,
    /// The resource did not match the requested MCP protected resource.
    #[error("ID-JAG resource does not match protected resource")]
    ResourceMismatch,
    /// The `client_id` claim was absent.
    #[error("ID-JAG client_id is missing")]
    MissingClientId,
    /// The asserted client did not match the client authenticated by the resource AS.
    #[error("ID-JAG client does not match authenticated OAuth client")]
    ClientMismatch,
    /// The `sub` claim was absent.
    #[error("ID-JAG subject is missing")]
    MissingSubject,
    /// The `jti` claim was absent.
    #[error("ID-JAG jti is missing")]
    MissingJwtId,
    /// The `iat` claim was absent.
    #[error("ID-JAG iat is missing")]
    MissingIssuedAt,
    /// The `exp` claim was absent.
    #[error("ID-JAG exp is missing")]
    MissingExpiration,
    /// The assertion issuance time is unacceptably in the future.
    #[error("ID-JAG issuance time is in the future")]
    IssuedInFuture,
    /// The assertion is not active yet.
    #[error("ID-JAG is not yet valid")]
    NotYetValid,
    /// The assertion has expired.
    #[error("ID-JAG has expired")]
    Expired,
    /// Temporal ordering or maximum lifetime was invalid.
    #[error("ID-JAG lifetime is invalid")]
    InvalidLifetime,
    /// The `scope` claim was absent, empty, oversized, or outside policy intersection.
    #[error("ID-JAG scope is invalid")]
    InvalidScope,
    /// Resource metadata could not be loaded.
    #[error("protected resource authorization policy is unavailable")]
    ResourcePolicyUnavailable,
    /// The replay store was unavailable.
    #[error("ID-JAG replay state is unavailable")]
    ReplayStateUnavailable,
    /// The issuer-scoped assertion JTI was already consumed.
    #[error("ID-JAG was replayed")]
    Replayed,
    /// Durable identity-link lookup failed.
    #[error("enterprise identity link is unavailable")]
    IdentityLinkUnavailable,
    /// The durable identity link is disabled or revoked.
    #[error("enterprise identity link is inactive")]
    IdentityLinkInactive,
    /// The durable link did not match the validated issuer and subject.
    #[error("enterprise identity link does not match assertion")]
    IdentityLinkMismatch,
    /// The durable link does not permit the authenticated client.
    #[error("enterprise identity link does not permit OAuth client")]
    IdentityLinkClientMismatch,
    /// The durable link does not permit the exact resource.
    #[error("enterprise identity link does not permit protected resource")]
    IdentityLinkResourceMismatch,
    /// Tenant entitlement lookup failed.
    #[error("enterprise tenant entitlement is unavailable")]
    TenantEntitlementUnavailable,
    /// Canonical user/tenant entitlement is no longer active.
    #[error("enterprise tenant entitlement is inactive")]
    TenantEntitlementInactive,
    /// Tenant entitlement did not match the identity link.
    #[error("enterprise tenant entitlement does not match identity link")]
    TenantEntitlementMismatch,
    /// A port returned malformed, unbounded, or zero-version state.
    #[error("enterprise authoritative state is invalid")]
    InvalidAuthoritativeState,
    /// Canonical principal construction failed.
    #[error("canonical enterprise principal could not be constructed")]
    PrincipalConstructionFailed,
}

/// Validates ID-JAGs and produces canonical resource-token issuance claims.
pub struct EnterpriseExchangeService<V, R, L, T, P, C> {
    config: EnterpriseAuthorizationConfig,
    verifier: V,
    resource_port: R,
    link_port: L,
    tenant_port: T,
    replay_port: P,
    client_port: C,
}

impl<V, R, L, T, P, C> EnterpriseExchangeService<V, R, L, T, P, C> {
    /// Creates the exchange service from explicit verification and live-state ports.
    #[must_use]
    pub fn new(
        config: EnterpriseAuthorizationConfig,
        verifier: V,
        resource_port: R,
        link_port: L,
        tenant_port: T,
        replay_port: P,
        client_port: C,
    ) -> Self {
        Self {
            config,
            verifier,
            resource_port,
            link_port,
            tenant_port,
            replay_port,
            client_port,
        }
    }
}

impl<V, R, L, T, P, C> EnterpriseExchangeService<V, R, L, T, P, C>
where
    V: IdJagSignatureVerifier,
    R: ResourceIssuerPort,
    L: EnterpriseIdentityLinkPort,
    T: TenantEntitlementPort,
    P: IdJagReplayPort,
    C: EnterpriseOAuthClientPort,
{
    /// Validates the complete enterprise delegation chain and constructs canonical token claims.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`EnterpriseAuthorizationError`] for negotiation, authentication,
    /// cryptographic, claim, replay, link, tenant, resource, time, or scope denial.
    #[expect(
        clippy::too_many_lines,
        reason = "the exchange keeps ordered negotiation, verification, replay, live-state, and claim checks visible"
    )]
    pub async fn exchange(
        &self,
        request: &EnterpriseExchangeRequest,
        client_authentication: &C::Authentication,
        now: OffsetDateTime,
        local_access_token_jwt_id: JwtId,
    ) -> Result<EnterpriseExchange, EnterpriseAuthorizationError> {
        if !request
            .request_context
            .negotiated_extensions()
            .extensions()
            .iter()
            .any(|extension| {
                extension.id().as_str() == ENTERPRISE_AUTHORIZATION_EXTENSION_ID
                    && extension.revision().as_str() == ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION
            })
        {
            return Err(EnterpriseAuthorizationError::ExtensionNotNegotiated);
        }

        let resource_policy = self
            .resource_port
            .resolve_resource(&request.resource)
            .await
            .map_err(|_| EnterpriseAuthorizationError::ResourcePolicyUnavailable)?;
        if resource_policy.resource() != &request.resource {
            return Err(EnterpriseAuthorizationError::InvalidAuthoritativeState);
        }

        let client = self
            .client_port
            .authenticate_client(client_authentication, &request.resource)
            .await
            .map_err(|_| EnterpriseAuthorizationError::OAuthClientUnavailable)?;
        let client_scopes = canonical_scopes(client.allowed_scopes.clone())?;
        if !client.active
            || client.authorization_revision == 0
            || client.resource != request.resource
            || client.issuer != *resource_policy.authorization_server_issuer()
            || client_scopes != client.allowed_scopes
        {
            return Err(EnterpriseAuthorizationError::OAuthClientUnavailable);
        }

        let signed = self
            .verifier
            .verify_signature(&request.assertion, &self.config.trusted_issuers)
            .await
            .map_err(EnterpriseAuthorizationError::VerificationFailed)?;
        let claims =
            self.validate_claims(signed, &resource_policy, &client, &request.resource, now)?;

        let replay_retain_until = claims
            .expires_at
            .checked_add(self.config.clock_skew)
            .ok_or(EnterpriseAuthorizationError::InvalidLifetime)?;
        match self
            .replay_port
            .consume_once(&claims.issuer, &claims.jwt_id, replay_retain_until)
            .await
            .map_err(|_| EnterpriseAuthorizationError::ReplayStateUnavailable)?
        {
            ReplayDecision::Fresh => {}
            ReplayDecision::Replayed => return Err(EnterpriseAuthorizationError::Replayed),
        }

        let link = self
            .link_port
            .load_live_link(&claims.issuer, &claims.subject)
            .await
            .map_err(|_| EnterpriseAuthorizationError::IdentityLinkUnavailable)?;
        if link.issuer != claims.issuer || link.external_subject != claims.subject {
            return Err(EnterpriseAuthorizationError::IdentityLinkMismatch);
        }
        if !link.active {
            return Err(EnterpriseAuthorizationError::IdentityLinkInactive);
        }
        if link
            .permitted_clients
            .binary_search(&claims.client_id)
            .is_err()
        {
            return Err(EnterpriseAuthorizationError::IdentityLinkClientMismatch);
        }
        if link
            .permitted_resources
            .binary_search(&claims.resource)
            .is_err()
        {
            return Err(EnterpriseAuthorizationError::IdentityLinkResourceMismatch);
        }

        let tenant = self
            .tenant_port
            .load_live_entitlement(link.local_subject, link.tenant_id)
            .await
            .map_err(|_| EnterpriseAuthorizationError::TenantEntitlementUnavailable)?;
        if tenant.local_subject != link.local_subject || tenant.tenant_id != link.tenant_id {
            return Err(EnterpriseAuthorizationError::TenantEntitlementMismatch);
        }
        if !tenant.active {
            return Err(EnterpriseAuthorizationError::TenantEntitlementInactive);
        }

        if request.requested_scopes.len() > MAX_SCOPES {
            return Err(EnterpriseAuthorizationError::InvalidScope);
        }
        let requested = canonical_scopes(request.requested_scopes.clone())?;
        let ceilings = [
            claims.scopes.as_slice(),
            resource_policy.allowed_scopes(),
            client.allowed_scopes.as_slice(),
            link.allowed_scopes.as_slice(),
            tenant.allowed_scopes.as_slice(),
        ];
        let authorized = intersect_scopes(&ceilings);
        let granted_scopes = if requested.is_empty() {
            authorized
        } else {
            let with_request = [requested.as_slice(), authorized.as_slice()];
            let granted = intersect_scopes(&with_request);
            if granted != requested {
                return Err(EnterpriseAuthorizationError::InvalidScope);
            }
            granted
        };
        if granted_scopes.is_empty() {
            return Err(EnterpriseAuthorizationError::InvalidScope);
        }

        let principal = Principal::new(
            link.local_subject,
            PrincipalKind::User,
            Some(link.tenant_id),
            AuthMethod::Jwt,
            now,
            AssuranceLevel::Aal1,
            granted_scopes.clone(),
        )
        .map_err(|_| EnterpriseAuthorizationError::PrincipalConstructionFailed)?;
        let expires_at = now
            .checked_add(self.config.access_token_lifetime)
            .ok_or(EnterpriseAuthorizationError::InvalidLifetime)?;
        let access_token_claims = AccessTokenClaims::new(AccessTokenClaimsInput {
            issuer: resource_policy.authorization_server_issuer().clone(),
            subject: link.public_subject.as_str().to_owned(),
            audience: claims.resource.clone(),
            expires_at,
            not_before: now,
            issued_at: now,
            jwt_id: local_access_token_jwt_id,
            client_id: claims.client_id.clone(),
            grant_id: link.grant_id,
            scopes: granted_scopes,
            auth_time: now,
            acr: "aal1".to_owned(),
            amr: vec![client_authentication_method(client.authentication_method).to_owned()],
        })
        .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?;
        let delegation = DelegationChainEvidence {
            enterprise_issuer: claims.issuer,
            external_subject_fingerprint: EvidenceFingerprint::from_domain_value(
                b"omnius:mcp:id-jag:subject:v1",
                claims.subject.as_str(),
            ),
            mcp_client_id: claims.client_id,
            resource: claims.resource,
            assertion_fingerprint: EvidenceFingerprint::from_domain_value(
                b"omnius:mcp:id-jag:jti:v1",
                claims.jwt_id.as_str(),
            ),
            identity_link_id: link.link_id,
            effective_subject: link.local_subject,
            tenant_id: link.tenant_id,
            link_version: link.link_version,
            revocation_version: link.revocation_version,
            policy_version: link.policy_version,
            tenant_authorization_revision: tenant.authorization_revision,
        };
        Ok(EnterpriseExchange {
            principal,
            access_token_claims,
            delegation,
        })
    }

    fn validate_claims(
        &self,
        signed: SignatureVerifiedIdJag,
        resource_policy: &ResourceAuthorizationPolicy,
        authenticated_client: &EnterpriseOAuthClientState,
        expected_resource: &ResourceUri,
        now: OffsetDateTime,
    ) -> Result<ValidatedIdJagClaims, EnterpriseAuthorizationError> {
        let token_type = signed
            .header
            .token_type
            .ok_or(EnterpriseAuthorizationError::MissingType)?;
        if token_type != ID_JAG_JOSE_TYPE {
            return Err(EnterpriseAuthorizationError::InvalidType);
        }
        let algorithm = signed
            .header
            .algorithm
            .ok_or(EnterpriseAuthorizationError::MissingAlgorithm)?;
        if !self.config.allowed_algorithms.contains(&algorithm) {
            return Err(EnterpriseAuthorizationError::DisallowedAlgorithm);
        }
        signed
            .header
            .key_id
            .ok_or(EnterpriseAuthorizationError::MissingKeyId)?;

        let payload = signed.payload;
        let issuer = payload
            .issuer
            .ok_or(EnterpriseAuthorizationError::MissingIssuer)?;
        if &issuer == resource_policy.authorization_server_issuer() {
            return Err(EnterpriseAuthorizationError::LocalTokenExchangeDenied);
        }
        if !self.config.trusted_issuers.contains(&issuer) {
            return Err(EnterpriseAuthorizationError::UntrustedIssuer);
        }
        let audiences = payload
            .audiences
            .ok_or(EnterpriseAuthorizationError::MissingAudience)?;
        if audiences.len() != 1
            || audiences.first() != Some(resource_policy.authorization_server_issuer())
        {
            return Err(EnterpriseAuthorizationError::AudienceMismatch);
        }
        let resource = payload
            .resource
            .ok_or(EnterpriseAuthorizationError::MissingResource)?;
        if &resource != expected_resource {
            return Err(EnterpriseAuthorizationError::ResourceMismatch);
        }
        let client_id = payload
            .client_id
            .ok_or(EnterpriseAuthorizationError::MissingClientId)?;
        if client_id != authenticated_client.client_id {
            return Err(EnterpriseAuthorizationError::ClientMismatch);
        }
        let subject = payload
            .subject
            .ok_or(EnterpriseAuthorizationError::MissingSubject)?;
        let jwt_id = payload
            .jwt_id
            .ok_or(EnterpriseAuthorizationError::MissingJwtId)?;
        let issued_at = payload
            .issued_at
            .ok_or(EnterpriseAuthorizationError::MissingIssuedAt)?;
        let not_before = payload.not_before;
        let expires_at = payload
            .expires_at
            .ok_or(EnterpriseAuthorizationError::MissingExpiration)?;
        if issued_at > now + self.config.clock_skew {
            return Err(EnterpriseAuthorizationError::IssuedInFuture);
        }
        if not_before.is_some_and(|not_before| not_before > now + self.config.clock_skew) {
            return Err(EnterpriseAuthorizationError::NotYetValid);
        }
        if expires_at <= now - self.config.clock_skew {
            return Err(EnterpriseAuthorizationError::Expired);
        }
        if expires_at <= issued_at
            || not_before.is_some_and(|not_before| expires_at <= not_before)
            || expires_at - issued_at > self.config.id_jag_max_lifetime
        {
            return Err(EnterpriseAuthorizationError::InvalidLifetime);
        }
        let scopes = payload
            .scopes
            .ok_or(EnterpriseAuthorizationError::InvalidScope)
            .and_then(canonical_scopes)?;
        if scopes.is_empty() {
            return Err(EnterpriseAuthorizationError::InvalidScope);
        }
        Ok(ValidatedIdJagClaims {
            issuer,
            subject,
            audience: resource_policy.authorization_server_issuer().clone(),
            resource,
            client_id,
            jwt_id,
            issued_at,
            not_before,
            expires_at,
            scopes,
        })
    }
}

/// Immutable digest of an already-redacted canonical argument summary.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ArgumentSummaryDigest([u8; 32]);

impl ArgumentSummaryDigest {
    /// Hashes a bounded, already-redacted canonical summary without retaining it.
    ///
    /// # Errors
    ///
    /// Returns [`EnterpriseIdentifierError::TooLong`] above 16 KiB.
    pub fn from_redacted_canonical(
        redacted_summary: &[u8],
    ) -> Result<Self, EnterpriseIdentifierError> {
        if redacted_summary.len() > MAX_REDACTED_ARGUMENT_SUMMARY_BYTES {
            return Err(EnterpriseIdentifierError::TooLong);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"omnius:mcp:argument-summary:v1");
        hasher.update([0]);
        hasher.update(redacted_summary);
        Ok(Self(hasher.finalize().into()))
    }

    /// Returns the fixed-size digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ArgumentSummaryDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArgumentSummaryDigest(<sha256>)")
    }
}

/// Explicit consent provenance; there is no implicit-enterprise-consent variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsentSource {
    /// Consent is not required by authoritative capability metadata.
    NotRequired,
    /// An interactive user decision bound to principal, tenant, client, and capability key.
    UserInteractive,
    /// An explicit enterprise policy decision identified by a bounded policy ID.
    EnterprisePolicy(CapabilityId),
}

/// Input to consent evaluation, separate from ordinary authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentQuery {
    /// Canonical effective user.
    pub subject: SubjectId,
    /// Authoritative tenant.
    pub tenant_id: TenantId,
    /// Authenticated MCP client.
    pub client_id: ClientId,
    /// Exact MCP operation.
    pub operation: McpOperation,
    /// Current registry-owned capability key.
    pub capability: CapabilityKey,
    /// Digest of the redacted canonical argument summary.
    pub argument_summary: ArgumentSummaryDigest,
}

/// Explicit consent decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentDecision {
    /// Whether consent was granted.
    pub granted: bool,
    /// Human or enterprise-policy source.
    pub source: ConsentSource,
    /// Capability key to which consent was bound.
    pub capability: CapabilityKey,
}

/// Value-free consent-store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise consent decision is unavailable")]
pub struct ConsentStoreError;

/// Consent policy port, intentionally distinct from ordinary authorization.
pub trait EnterpriseConsentPort: Send + Sync {
    /// Resolves explicit user or enterprise-policy consent.
    fn resolve_consent(
        &self,
        query: &ConsentQuery,
    ) -> impl Future<Output = Result<ConsentDecision, ConsentStoreError>> + Send;
}

/// One trusted registry projection for a requested capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseCapabilitySnapshot {
    document: CapabilityDocument,
    visibility: CapabilityVisibility,
}

impl EnterpriseCapabilitySnapshot {
    /// Constructs a registry-owned snapshot.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when the capability declaration is invalid.
    pub fn new(
        document: CapabilityDocument,
        visibility: CapabilityVisibility,
    ) -> Result<Self, EnterpriseRegistryError> {
        document.validate().map_err(|_| EnterpriseRegistryError)?;
        Ok(Self {
            document,
            visibility,
        })
    }

    /// Returns the authoritative capability document.
    #[must_use]
    pub const fn document(&self) -> &CapabilityDocument {
        &self.document
    }

    /// Returns registry-owned public or tenant-private visibility.
    #[must_use]
    pub const fn visibility(&self) -> CapabilityVisibility {
        self.visibility
    }
}

/// Principal- and request-bound registry-filtered catalog snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseCatalogSnapshot {
    exposure: Exposure,
    request_id: RequestId,
    principal_subject: SubjectId,
    tenant_id: Option<TenantId>,
    visible_capabilities: Vec<CapabilityKey>,
}

impl EnterpriseCatalogSnapshot {
    /// Constructs one deterministic catalog snapshot after registry visibility filtering.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for an oversized or noncanonical visible key set.
    pub fn new(
        request_context: &McpRequestContext,
        exposure: Exposure,
        visible_capabilities: Vec<CapabilityKey>,
    ) -> Result<Self, EnterpriseRegistryError> {
        if visible_capabilities.len() > MAX_VISIBLE_CATALOG_CAPABILITIES
            || visible_capabilities
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(EnterpriseRegistryError);
        }
        let invocation = request_context.canonical().invocation();
        Ok(Self {
            exposure,
            request_id: invocation.request_id(),
            principal_subject: invocation.principal().subject_id,
            tenant_id: invocation.tenant_id(),
            visible_capabilities,
        })
    }

    /// Returns the registry-filtered visible capability keys.
    #[must_use]
    pub fn visible_capabilities(&self) -> &[CapabilityKey] {
        &self.visible_capabilities
    }

    fn is_bound_to(&self, request_context: &McpRequestContext, exposure: Exposure) -> bool {
        let invocation = request_context.canonical().invocation();
        self.exposure == exposure
            && self.request_id == invocation.request_id()
            && self.principal_subject == invocation.principal().subject_id
            && self.tenant_id == invocation.tenant_id()
    }
}

/// Value-free capability-registry resolution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise capability registry is unavailable")]
pub struct EnterpriseRegistryError;

/// Registry boundary that resolves only fresh, authorization-filtered capability metadata.
pub trait EnterpriseCapabilityRegistryPort: Send + Sync {
    /// Resolves a complete principal- and tenant-filtered catalog for this exact request.
    fn resolve_catalog(
        &self,
        request_context: &McpRequestContext,
        exposure: Exposure,
    ) -> impl Future<Output = Result<EnterpriseCatalogSnapshot, EnterpriseRegistryError>> + Send;

    /// Resolves one exact capability key for the canonical request context.
    fn resolve_capability(
        &self,
        request_context: &McpRequestContext,
        key: &CapabilityKey,
    ) -> impl Future<Output = Result<EnterpriseCapabilitySnapshot, EnterpriseRegistryError>> + Send;
}

/// Invocation target selected by protocol routing, never by capability metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterpriseInvocationTarget {
    /// One registry catalog projection.
    Catalog(Exposure),
    /// One exact registry capability revision.
    Capability(CapabilityKey),
}

/// Registry-derived ordinary authorization target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseAuthorizationTarget {
    operation: McpOperation,
    exposure: Exposure,
    catalog: Option<EnterpriseCatalogSnapshot>,
    capability: Option<CapabilityDocument>,
}

impl EnterpriseAuthorizationTarget {
    /// Returns the exact MCP operation.
    #[must_use]
    pub const fn operation(&self) -> McpOperation {
        self.operation
    }

    /// Returns the required MCP projection.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }

    /// Returns the registry-filtered catalog for list operations.
    #[must_use]
    pub const fn catalog(&self) -> Option<&EnterpriseCatalogSnapshot> {
        self.catalog.as_ref()
    }

    /// Returns registry metadata for targeted operations.
    #[must_use]
    pub const fn capability(&self) -> Option<&CapabilityDocument> {
        self.capability.as_ref()
    }
}

/// Query that revalidates a verified enterprise access token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseLiveStateQuery {
    /// Local access-token JTI.
    pub access_token_jwt_id: JwtId,
    /// Durable OAuth grant that identifies the enterprise link.
    pub grant_id: GrantId,
    /// Canonical effective user.
    pub subject: SubjectId,
    /// Authoritative tenant.
    pub tenant_id: TenantId,
    /// Verified OAuth client.
    pub client_id: ClientId,
    /// Exact protected resource.
    pub resource: ResourceUri,
}

/// One atomic live-state decision preventing revocation races.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterpriseLiveState {
    /// Whether the local access-token JTI and grant remain active.
    pub access_token_active: bool,
    /// Whether the enterprise identity link remains active.
    pub identity_link_active: bool,
    /// Whether tenant membership and entitlement remain active.
    pub tenant_entitlement_active: bool,
    /// Current enterprise authorization-policy version.
    pub policy_version: u64,
    /// Current tenant authorization revision.
    pub tenant_authorization_revision: u64,
}

/// Value-free live-state store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise live authorization state is unavailable")]
pub struct EnterpriseLiveStateError;

/// Atomic live authorization check used on every resource request.
pub trait EnterpriseLiveStatePort: Send + Sync {
    /// Checks token, grant, identity-link, tenant, policy, and revocation state together.
    fn check_live_state(
        &self,
        query: &EnterpriseLiveStateQuery,
    ) -> impl Future<Output = Result<EnterpriseLiveState, EnterpriseLiveStateError>> + Send;
}

/// Audit decision classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseAuditDecision {
    /// The operation was denied.
    Deny,
    /// The operation was authorized.
    Allow,
}

/// Audit result classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseAuditResult {
    /// Live delegation state was inactive.
    Revoked,
    /// Ordinary authorization denied or metadata was unavailable.
    PolicyDenied,
    /// Explicit consent was denied.
    ConsentDenied,
    /// The protected action was atomically admitted for execution.
    Authorized,
}

/// Bounded typed enterprise audit event containing no token, email, or full arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseAuditEvent {
    /// Authenticated OAuth client.
    pub client_id: ClientId,
    /// Canonical effective user.
    pub principal_subject: SubjectId,
    /// Authoritative tenant.
    pub tenant_id: TenantId,
    /// Exact MCP resource.
    pub resource: ResourceUri,
    /// Exact MCP operation.
    pub operation: McpOperation,
    /// Attempted catalog or current capability target.
    pub target: EnterpriseInvocationTarget,
    /// Authorization decision.
    pub decision: EnterpriseAuditDecision,
    /// Stable result class.
    pub result: EnterpriseAuditResult,
    /// Canonical request identifier.
    pub request_id: AuditCorrelationId,
    /// Canonical trace identifier.
    pub trace_id: AuditCorrelationId,
    /// Explicit extension identifier.
    pub extension_id: &'static str,
    /// Exact extension revision.
    pub extension_revision: &'static str,
    /// Consent source, if evaluated.
    pub consent_source: Option<ConsentSource>,
    /// Ordinary/enterprise policy version.
    pub policy_version: u64,
    /// Tenant authorization revision.
    pub tenant_authorization_revision: u64,
    /// Digest of an already-redacted canonical argument summary.
    pub argument_summary: ArgumentSummaryDigest,
    /// Hash of the access-token JTI rather than any token or raw identifier.
    pub access_token_fingerprint: EvidenceFingerprint,
}

/// Value-free audited execution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("enterprise audited execution failed")]
pub struct EnterpriseExecutionError;

/// Single atomic boundary for protected execution and its successful audit event.
pub trait EnterpriseAuditedExecution: Send {
    /// Protected action output.
    type Output;

    /// Records a denied attempt durably.
    fn record_denial(
        &mut self,
        event: EnterpriseAuditEvent,
    ) -> impl Future<Output = Result<(), EnterpriseExecutionError>> + Send;

    /// Executes the protected action and appends its audit event in one atomic boundary.
    fn execute_authorized(
        &mut self,
        action: EnterpriseAuthorizedAction,
        event: EnterpriseAuditEvent,
    ) -> impl Future<Output = Result<Self::Output, EnterpriseExecutionError>> + Send;
}

/// Non-cloneable authorized action consumable only by [`EnterpriseAuditedExecution`].
pub struct EnterpriseAuthorizedAction {
    principal: Principal,
    operation: McpOperation,
    target: EnterpriseInvocationTarget,
    authorization_target: EnterpriseAuthorizationTarget,
    consent_source: ConsentSource,
}

impl EnterpriseAuthorizedAction {
    /// Returns the canonical principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the exact MCP operation.
    #[must_use]
    pub const fn operation(&self) -> McpOperation {
        self.operation
    }

    /// Returns the authorized registry target.
    #[must_use]
    pub const fn target(&self) -> &EnterpriseInvocationTarget {
        &self.target
    }

    /// Returns the registry-derived target that ordinary authorization evaluated.
    #[must_use]
    pub const fn authorization_target(&self) -> &EnterpriseAuthorizationTarget {
        &self.authorization_target
    }

    /// Returns current explicit consent provenance.
    #[must_use]
    pub const fn consent_source(&self) -> &ConsentSource {
        &self.consent_source
    }
}

impl fmt::Debug for EnterpriseAuthorizedAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnterpriseAuthorizedAction([REDACTED])")
    }
}

/// Invocation authorization request containing only bounded caller inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseInvocationRequest {
    /// Exact MCP operation selected by protocol dispatch.
    pub operation: McpOperation,
    /// Catalog or registry key selected by protocol dispatch.
    pub target: EnterpriseInvocationTarget,
    /// Digest of already-redacted canonical arguments.
    pub argument_summary: ArgumentSummaryDigest,
}

/// Invocation authorization denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnterpriseInvocationError {
    /// Canonical request, identity, operation, or target evidence was inconsistent.
    #[error("enterprise invocation request is invalid")]
    InvalidRequest,
    /// Live revocation state could not be checked.
    #[error("enterprise live authorization state is unavailable")]
    LiveStateUnavailable,
    /// Token, grant, identity link, or tenant entitlement is revoked.
    #[error("enterprise delegation is revoked")]
    Revoked,
    /// Capability registry or ordinary authorization could not be evaluated.
    #[error("ordinary authorization policy is unavailable")]
    AuthorizationUnavailable,
    /// Ordinary authorization denied the operation.
    #[error("ordinary authorization denied MCP operation")]
    AuthorizationDenied,
    /// Consent could not be evaluated.
    #[error("enterprise consent policy is unavailable")]
    ConsentUnavailable,
    /// Consent was denied, implicit, or bound to a stale capability key.
    #[error("required enterprise consent was denied")]
    ConsentDenied,
    /// A denial audit could not be persisted.
    #[error("transactional enterprise audit failed")]
    AuditUnavailable,
    /// The atomic protected execution and audit boundary failed.
    #[error("enterprise protected execution failed")]
    ExecutionFailed,
}

/// Applies live revocation, registry metadata, ordinary authorization, consent, and audit.
pub struct EnterpriseInvocationAuthorizer<L, G, A, C> {
    live_state: L,
    registry: G,
    authorization: A,
    consent: C,
}

impl<L, G, A, C> EnterpriseInvocationAuthorizer<L, G, A, C> {
    /// Creates the invocation guard from live, registry, ordinary-policy, and consent ports.
    #[must_use]
    pub const fn new(live_state: L, registry: G, authorization: A, consent: C) -> Self {
        Self {
            live_state,
            registry,
            authorization,
            consent,
        }
    }
}

impl<L, G, A, C> EnterpriseInvocationAuthorizer<L, G, A, C>
where
    L: EnterpriseLiveStatePort,
    G: EnterpriseCapabilityRegistryPort,
    A: McpOperationAuthorizer<EnterpriseAuthorizationTarget>,
    C: EnterpriseConsentPort,
{
    /// Authorizes and executes one MCP operation through an atomic audit boundary.
    ///
    /// # Errors
    ///
    /// Fails closed on request/identity mismatch, revocation, registry, ordinary policy,
    /// consent, denial-audit, or protected execution/audit failure.
    #[expect(
        clippy::too_many_lines,
        reason = "one fail-closed flow keeps identity, registry, policy, consent, audit, and execution ordering explicit"
    )]
    pub async fn authorize_and_execute<E>(
        &self,
        request_context: &McpRequestContext,
        identity: &McpAuthenticatedIdentity,
        request: &EnterpriseInvocationRequest,
        execution: &mut E,
    ) -> Result<E::Output, EnterpriseInvocationError>
    where
        E: EnterpriseAuditedExecution,
    {
        if !request_context
            .negotiated_extensions()
            .extensions()
            .iter()
            .any(|extension| {
                extension.id().as_str() == ENTERPRISE_AUTHORIZATION_EXTENSION_ID
                    && extension.revision().as_str() == ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION
            })
        {
            return Err(EnterpriseInvocationError::InvalidRequest);
        }
        let invocation = request_context.canonical().invocation();
        let tenant_id = invocation
            .tenant_id()
            .ok_or(EnterpriseInvocationError::InvalidRequest)?;
        if invocation.principal() != identity.principal()
            || identity.principal().tenant_id != Some(tenant_id)
            || identity.resource() != identity.audience()
        {
            return Err(EnterpriseInvocationError::InvalidRequest);
        }

        let live = self
            .live_state
            .check_live_state(&EnterpriseLiveStateQuery {
                access_token_jwt_id: *identity.jwt_id(),
                grant_id: *identity.grant_id(),
                subject: identity.principal().subject_id,
                tenant_id,
                client_id: identity.client_id().clone(),
                resource: identity.resource().clone(),
            })
            .await
            .map_err(|_| EnterpriseInvocationError::LiveStateUnavailable)?;
        if !live.access_token_active
            || !live.identity_link_active
            || !live.tenant_entitlement_active
            || live.policy_version == 0
            || live.tenant_authorization_revision == 0
        {
            let event = build_audit_event(
                request_context,
                identity,
                request,
                EnterpriseAuditDecision::Deny,
                EnterpriseAuditResult::Revoked,
                None,
                &live,
            )?;
            execution
                .record_denial(event)
                .await
                .map_err(|_| EnterpriseInvocationError::AuditUnavailable)?;
            return Err(EnterpriseInvocationError::Revoked);
        }

        let exposure = operation_exposure(request.operation);
        let (authorization_target, visibility, consent_key, requires_consent) =
            match (&request.operation, &request.target) {
                (
                    McpOperation::ListResources
                    | McpOperation::ListPrompts
                    | McpOperation::ListTools,
                    EnterpriseInvocationTarget::Catalog(target_exposure),
                ) if *target_exposure == exposure => {
                    let catalog = self
                        .registry
                        .resolve_catalog(request_context, exposure)
                        .await
                        .map_err(|_| EnterpriseInvocationError::AuthorizationUnavailable)?;
                    if !catalog.is_bound_to(request_context, exposure) {
                        return Err(EnterpriseInvocationError::AuthorizationDenied);
                    }
                    (
                        EnterpriseAuthorizationTarget {
                            operation: request.operation,
                            exposure,
                            catalog: Some(catalog),
                            capability: None,
                        },
                        CapabilityVisibility::TenantPrivate(tenant_id),
                        None,
                        false,
                    )
                }
                (
                    McpOperation::ReadResource | McpOperation::GetPrompt | McpOperation::CallTool,
                    EnterpriseInvocationTarget::Capability(key),
                ) => {
                    let snapshot = self
                        .registry
                        .resolve_capability(request_context, key)
                        .await
                        .map_err(|_| EnterpriseInvocationError::AuthorizationUnavailable)?;
                    let document = snapshot.document();
                    if document.key() != *key
                        || !document.exposures.contains(&exposure)
                        || !document
                            .tenant_modes
                            .contains(&request_context.canonical().tenant_mode())
                    {
                        return Err(EnterpriseInvocationError::AuthorizationDenied);
                    }
                    let requires_consent = document.confirmation != ConfirmationPolicy::Never;
                    (
                        EnterpriseAuthorizationTarget {
                            operation: request.operation,
                            exposure,
                            catalog: None,
                            capability: Some(document.clone()),
                        },
                        snapshot.visibility(),
                        Some(key.clone()),
                        requires_consent,
                    )
                }
                _ => return Err(EnterpriseInvocationError::InvalidRequest),
            };

        let ordinary_authorized =
            TenantGuard
                .authorize(identity, Some(tenant_id))
                .and_then(|tenant| {
                    OperationGuard.authorize(
                        tenant,
                        request.operation,
                        visibility,
                        &authorization_target,
                        &self.authorization,
                    )
                });
        if ordinary_authorized.is_err() {
            let event = build_audit_event(
                request_context,
                identity,
                request,
                EnterpriseAuditDecision::Deny,
                EnterpriseAuditResult::PolicyDenied,
                None,
                &live,
            )?;
            execution
                .record_denial(event)
                .await
                .map_err(|_| EnterpriseInvocationError::AuditUnavailable)?;
            return Err(EnterpriseInvocationError::AuthorizationDenied);
        }

        let consent_source = if requires_consent {
            let capability = consent_key.ok_or(EnterpriseInvocationError::AuthorizationDenied)?;
            let decision = self
                .consent
                .resolve_consent(&ConsentQuery {
                    subject: identity.principal().subject_id,
                    tenant_id,
                    client_id: identity.client_id().clone(),
                    operation: request.operation,
                    capability: capability.clone(),
                    argument_summary: request.argument_summary,
                })
                .await
                .map_err(|_| EnterpriseInvocationError::ConsentUnavailable)?;
            if !decision.granted
                || decision.capability != capability
                || matches!(decision.source, ConsentSource::NotRequired)
            {
                let event = build_audit_event(
                    request_context,
                    identity,
                    request,
                    EnterpriseAuditDecision::Deny,
                    EnterpriseAuditResult::ConsentDenied,
                    Some(decision.source),
                    &live,
                )?;
                execution
                    .record_denial(event)
                    .await
                    .map_err(|_| EnterpriseInvocationError::AuditUnavailable)?;
                return Err(EnterpriseInvocationError::ConsentDenied);
            }
            decision.source
        } else {
            ConsentSource::NotRequired
        };

        let event = build_audit_event(
            request_context,
            identity,
            request,
            EnterpriseAuditDecision::Allow,
            EnterpriseAuditResult::Authorized,
            Some(consent_source.clone()),
            &live,
        )?;
        execution
            .execute_authorized(
                EnterpriseAuthorizedAction {
                    principal: identity.principal().clone(),
                    operation: request.operation,
                    target: request.target.clone(),
                    authorization_target,
                    consent_source,
                },
                event,
            )
            .await
            .map_err(|_| EnterpriseInvocationError::ExecutionFailed)
    }
}

fn operation_exposure(operation: McpOperation) -> Exposure {
    match operation {
        McpOperation::ListResources | McpOperation::ReadResource => Exposure::McpResource,
        McpOperation::ListPrompts | McpOperation::GetPrompt => Exposure::McpPrompt,
        McpOperation::ListTools | McpOperation::CallTool => Exposure::McpTool,
    }
}

fn build_audit_event(
    request_context: &McpRequestContext,
    identity: &McpAuthenticatedIdentity,
    request: &EnterpriseInvocationRequest,
    decision: EnterpriseAuditDecision,
    result: EnterpriseAuditResult,
    consent_source: Option<ConsentSource>,
    live: &EnterpriseLiveState,
) -> Result<EnterpriseAuditEvent, EnterpriseInvocationError> {
    let invocation = request_context.canonical().invocation();
    let tenant_id = invocation
        .tenant_id()
        .ok_or(EnterpriseInvocationError::InvalidRequest)?;
    let request_id = AuditCorrelationId::new(invocation.request_id().to_string())
        .map_err(|_| EnterpriseInvocationError::InvalidRequest)?;
    let trace_id =
        AuditCorrelationId::new(invocation.trace_context().traceparent().as_str().to_owned())
            .map_err(|_| EnterpriseInvocationError::InvalidRequest)?;
    let access_token_jwt_id = identity.jwt_id().as_uuid().to_string();
    Ok(EnterpriseAuditEvent {
        client_id: identity.client_id().clone(),
        principal_subject: identity.principal().subject_id,
        tenant_id,
        resource: identity.resource().clone(),
        operation: request.operation,
        target: request.target.clone(),
        decision,
        result,
        request_id,
        trace_id,
        extension_id: ENTERPRISE_AUTHORIZATION_EXTENSION_ID,
        extension_revision: ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION,
        consent_source,
        policy_version: live.policy_version,
        tenant_authorization_revision: live.tenant_authorization_revision,
        argument_summary: request.argument_summary,
        access_token_fingerprint: EvidenceFingerprint::from_domain_value(
            b"omnius:mcp:access-token:jti:v1",
            &access_token_jwt_id,
        ),
    })
}

fn canonical_scopes(mut scopes: Vec<Scope>) -> Result<Vec<Scope>, EnterpriseAuthorizationError> {
    if scopes.len() > MAX_SCOPES {
        return Err(EnterpriseAuthorizationError::InvalidAuthoritativeState);
    }
    scopes.sort_unstable();
    scopes.dedup();
    Ok(scopes)
}

fn client_authentication_method(method: OAuthClientAuthenticationMethod) -> &'static str {
    match method {
        OAuthClientAuthenticationMethod::ClientSecretBasic => "client_secret_basic",
        OAuthClientAuthenticationMethod::ClientSecretPost => "client_secret_post",
        OAuthClientAuthenticationMethod::PrivateKeyJwt => "private_key_jwt",
        OAuthClientAuthenticationMethod::MutualTls => "tls_client_auth",
    }
}
fn canonical_values<T: Ord>(
    mut values: Vec<T>,
    max: usize,
) -> Result<Vec<T>, EnterpriseAuthorizationError> {
    values.sort_unstable();
    values.dedup();
    if values.len() > max {
        return Err(EnterpriseAuthorizationError::InvalidAuthoritativeState);
    }
    Ok(values)
}

fn intersect_scopes(scope_sets: &[&[Scope]]) -> Vec<Scope> {
    let Some((first, rest)) = scope_sets.split_first() else {
        return Vec::new();
    };
    let mut intersection = first.to_vec();
    intersection.retain(|scope| rest.iter().all(|set| set.binary_search(scope).is_ok()));
    intersection
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_is_exact_and_sensitive_values_are_redacted() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            IdJagJwtBearerGrant::new("urn:ietf:params:oauth:grant-type:token-exchange"),
            Err(EnterpriseAuthorizationError::UnsupportedGrant)
        );
        assert!(IdJagJwtBearerGrant::new(JWT_BEARER_GRANT_TYPE).is_ok());

        let token = CompactIdJag::new("header.payload.signature")?;
        let subject = ExternalSubjectId::new("employee-123")?;
        assert_eq!(format!("{token:?}"), "CompactIdJag(<redacted>)");
        assert_eq!(format!("{subject:?}"), "ExternalSubjectId(<redacted>)");
        Ok(())
    }

    #[test]
    fn configuration_forbids_symmetric_signatures_and_subsecond_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IssuerUri::parse("https://idp.example", true)?;
        assert_eq!(
            EnterpriseAuthorizationConfig::new(
                vec![issuer.clone()],
                vec![SignatureAlgorithm::Hs256],
                Duration::minutes(5),
                Duration::seconds(30),
                Duration::minutes(5),
            ),
            Err(EnterpriseConfigError::InvalidAlgorithms)
        );
        assert_eq!(
            EnterpriseAuthorizationConfig::new(
                vec![issuer],
                vec![SignatureAlgorithm::Es256],
                Duration::milliseconds(999),
                Duration::seconds(30),
                Duration::minutes(5),
            ),
            Err(EnterpriseConfigError::InvalidLifetime)
        );
        Ok(())
    }
}
