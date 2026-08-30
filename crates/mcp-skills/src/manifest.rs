use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use omnius_agent_capability_registry::{
    CapabilityDocument, CapabilityKey, CapabilityRegistry, DataPolicyRef, Exposure,
    MAX_PERMISSIONS, Permission,
};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::isolation::{ExecutableFormat, ExecutionProfile, IsolationError};
use crate::negotiation::{SKILLS_EXTENSION_REVISION, SkillsExtensionPolicy};
use crate::package::{InventoryError, PackageEntry, sha256_digest, validate_inventory};

/// Maximum canonical signed manifest bytes.
pub const MAX_SKILL_MANIFEST_BYTES: usize = 256 * 1024;
/// Maximum retained forward-compatible manifest fields.
pub const MAX_EXTENSION_FIELDS: usize = 32;
/// Maximum recursive depth accepted in untrusted JSON-shaped metadata.
pub const MAX_UNTRUSTED_VALUE_DEPTH: usize = 32;
/// Maximum JSON values and object members accepted in untrusted metadata.
pub const MAX_UNTRUSTED_VALUE_NODES: usize = 4_096;
/// Maximum capability requests in one Skill.
pub const MAX_SKILL_CAPABILITIES: usize = 64;

/// Signed envelope for versioned Skill metadata and static inventory.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSkillManifest {
    /// Non-secret identifier for the signing key.
    pub key_id: String,
    /// Signature algorithm. Only Ed25519 is admitted.
    pub algorithm: String,
    /// Detached signature encoded for the deployment verifier.
    pub signature: String,
    /// Signed manifest payload.
    pub payload: SkillManifest,
}

impl fmt::Debug for SignedSkillManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedSkillManifest([redacted])")
    }
}

/// Signed, versioned, bounded Skill package declaration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillManifest {
    /// Exact experimental Skills extension revision.
    pub extension_revision: String,
    /// Stable Skill identifier.
    pub skill_id: String,
    /// Versioned `skill://` URI scoped to one MCP server.
    pub uri: Url,
    /// Semantic Skill version.
    pub version: String,
    /// Human-readable name, equal to signed `SKILL.md` frontmatter.
    pub name: String,
    /// Human-readable description, equal to signed `SKILL.md` frontmatter.
    pub description: String,
    /// Verbatim JSON representation of signed `SKILL.md` YAML frontmatter.
    pub frontmatter: Value,
    /// Aggregate immutable package digest.
    pub package_digest: String,
    /// Complete bounded static inventory.
    pub inventory: Vec<PackageEntry>,
    /// Requested registry capability ceilings. These declarations never grant authority.
    #[serde(default)]
    pub capabilities: Vec<CapabilityRequest>,
    /// Data-only resource profile. Executable declarations are unsupported and not sandboxed.
    pub execution: ExecutionProfile,
    /// Safely retained forward-compatible `x-` fields.
    #[serde(flatten)]
    pub unknown_fields: BTreeMap<String, Value>,
}

/// Exact registry capability revision, exposure, and permission ceiling requested by a Skill.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    /// Exact capability-registry revision. An identifier without a revision is never accepted.
    pub key: CapabilityKey,
    /// Existing MCP surface through which the capability is already exposed.
    pub exposure: SkillExposure,
    /// Sorted, duplicate-free permission ceiling requested by the untrusted package.
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

/// Existing MCP exposure selected by a Skill request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillExposure {
    /// Existing MCP tool exposure.
    McpTool,
    /// Existing MCP resource exposure.
    McpResource,
    /// Existing MCP prompt exposure.
    McpPrompt,
}

impl SkillExposure {
    /// Returns the authoritative registry exposure represented by this request.
    #[must_use]
    pub const fn registry_exposure(self) -> Exposure {
        match self {
            Self::McpTool => Exposure::McpTool,
            Self::McpResource => Exposure::McpResource,
            Self::McpPrompt => Exposure::McpPrompt,
        }
    }
}

/// Deployment-owned identity for one opt-in Skills installation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillServerIdentity {
    server_id: String,
    installation_id: String,
}

impl SkillServerIdentity {
    /// Validates the stable server and installation identities.
    ///
    /// # Errors
    ///
    /// Returns a fixed error for empty, oversized, or malformed identifiers.
    pub fn try_new(
        server_id: impl Into<String>,
        installation_id: impl Into<String>,
    ) -> Result<Self, BindingError> {
        let server_id = server_id.into();
        let installation_id = installation_id.into();
        if !is_identifier(&server_id) || !is_identifier(&installation_id) {
            return Err(BindingError);
        }
        Ok(Self {
            server_id,
            installation_id,
        })
    }

    /// Borrows the stable MCP server identity.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Borrows the stable extension installation identity.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
}

impl fmt::Debug for SkillServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillServerIdentity([redacted])")
    }
}

/// Canonical tenant, principal, server, and installation binding for every Skill proof or record.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "explicit *_id names preserve canonical identity semantics and stable serialized fields"
)]
pub struct SkillBinding {
    server_id: String,
    installation_id: String,
    tenant_id: TenantId,
    principal_id: SubjectId,
}

impl SkillBinding {
    /// Derives a binding solely from deployment identity and canonical MCP request identity.
    ///
    /// # Errors
    ///
    /// Returns a fixed error when the request has no canonical tenant context.
    pub fn from_request(
        server: &SkillServerIdentity,
        request: &McpRequestContext,
    ) -> Result<Self, BindingError> {
        let invocation = request.canonical().invocation();
        let tenant_id = invocation.tenant_id().ok_or(BindingError)?;
        Ok(Self {
            server_id: server.server_id.clone(),
            installation_id: server.installation_id.clone(),
            tenant_id,
            principal_id: invocation.principal().subject_id,
        })
    }

    /// Requires this proof to match the current canonical request and deployment identity exactly.
    ///
    /// # Errors
    ///
    /// Returns a fixed error for any tenant, principal, server, or installation mismatch.
    pub fn require_request(
        &self,
        server: &SkillServerIdentity,
        request: &McpRequestContext,
    ) -> Result<(), BindingError> {
        if Self::from_request(server, request)? != *self {
            return Err(BindingError);
        }
        Ok(())
    }

    /// Borrows the MCP server identity.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Borrows the extension installation identity.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the canonical tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the canonical principal identity.
    #[must_use]
    pub const fn principal_id(&self) -> SubjectId {
        self.principal_id
    }
}

impl fmt::Debug for SkillBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillBinding([redacted])")
    }
}

/// Fixed, value-free canonical binding failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill identity binding is invalid")]
pub struct BindingError;

/// Verified signature and signed-payload provenance retained through every package stage.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillProvenance {
    signer_key_id: String,
    signature_algorithm: String,
    signature: String,
    manifest_digest: String,
}

impl SkillProvenance {
    /// Borrows the non-secret signer key identifier.
    #[must_use]
    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    /// Borrows the admitted signature algorithm.
    #[must_use]
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    /// Borrows the verified detached signature for durable provenance retention.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Borrows the lowercase SHA-256 digest of the signed typed payload.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
}

impl fmt::Debug for SkillProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillProvenance([redacted])")
    }
}

/// Deployment signature verification boundary.
pub trait ManifestSignatureVerifier {
    /// Verifies a detached signature over canonical typed payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureVerificationError`] when the algorithm, key, payload, or signature cannot
    /// be verified.
    fn verify(
        &self,
        key_id: &str,
        algorithm: &str,
        signed_payload: &[u8],
        signature: &str,
    ) -> Result<(), SignatureVerificationError>;
}

/// Redacted signature failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill manifest signature verification failed")]
pub struct SignatureVerificationError;

/// Signer trust decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustStatus {
    /// Signer is trusted for this exact canonical binding and Skill identity.
    Trusted,
    /// Signer is unknown, expired, or not trusted for this scope.
    Untrusted,
}

/// Deployment trust-store boundary.
pub trait SkillTrustStore {
    /// Looks up signer trust under the complete canonical binding.
    ///
    /// # Errors
    ///
    /// Returns [`TrustStoreError`] when the current scoped signer decision cannot be loaded.
    fn signer_status(
        &self,
        binding: &SkillBinding,
        key_id: &str,
        skill_uri: &str,
    ) -> Result<TrustStatus, TrustStoreError>;
}

/// Redacted trust-store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill trust store unavailable")]
pub struct TrustStoreError;

/// Package/signature revocation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationStatus {
    /// Neither signer nor package is revoked in this scope.
    Active,
    /// Signer, Skill version, or package has been revoked.
    Revoked,
}

/// Durable revocation boundary.
pub trait SkillRevocationRepository {
    /// Checks revocation under binding, version, package digest, and verified provenance.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationRepositoryError`] when current scoped revocation state cannot be loaded.
    fn status(
        &self,
        binding: &SkillBinding,
        skill_uri: &str,
        version: &str,
        package_digest: &str,
        provenance: &SkillProvenance,
    ) -> Result<RevocationStatus, RevocationRepositoryError>;
}

/// Redacted revocation repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill revocation repository unavailable")]
pub struct RevocationRepositoryError;

/// Canonical principal/server policy boundary layered over registry-owned capability documents.
pub trait SkillPrincipalPolicy {
    /// Returns the permission set currently allowed for this principal, server, and exact document.
    ///
    /// Returning success authorizes use of the capability itself. The returned permissions are
    /// intersected with both the registry document and the untrusted manifest ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityAuthorizationError`] when policy denies the capability or cannot produce
    /// a current permission set.
    fn allowed_permissions(
        &self,
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        document: &CapabilityDocument,
        exposure: SkillExposure,
    ) -> Result<BTreeSet<Permission>, CapabilityAuthorizationError>;
}

/// Redacted capability denial or policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill capability request denied")]
pub struct CapabilityAuthorizationError;

/// Effective request-scoped capability grant derived from the immutable registry and current policy.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedSkillCapability {
    key: CapabilityKey,
    exposure: SkillExposure,
    permissions: Vec<Permission>,
    data_policy: DataPolicyRef,
}

impl AuthorizedSkillCapability {
    /// Borrows the exact registry capability revision.
    #[must_use]
    pub const fn key(&self) -> &CapabilityKey {
        &self.key
    }

    /// Returns the admitted MCP exposure.
    #[must_use]
    pub const fn exposure(&self) -> SkillExposure {
        self.exposure
    }

    /// Borrows the effective permission intersection in deterministic order.
    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// Borrows the canonical request data-policy reference.
    #[must_use]
    pub const fn data_policy(&self) -> &DataPolicyRef {
        &self.data_policy
    }
}

impl fmt::Debug for AuthorizedSkillCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedSkillCapability([redacted])")
    }
}

/// A Skill admitted for one exact tenant, principal, server, and installation binding.
#[derive(Clone, PartialEq)]
pub struct AdmittedSkill {
    binding: SkillBinding,
    provenance: SkillProvenance,
    manifest: SkillManifest,
    capabilities: Vec<AuthorizedSkillCapability>,
}

impl AdmittedSkill {
    /// Borrows the canonical security binding.
    #[must_use]
    pub const fn binding(&self) -> &SkillBinding {
        &self.binding
    }

    /// Borrows verified signature provenance.
    #[must_use]
    pub const fn provenance(&self) -> &SkillProvenance {
        &self.provenance
    }

    /// Borrows the admitted signed manifest.
    #[must_use]
    pub const fn manifest(&self) -> &SkillManifest {
        &self.manifest
    }

    /// Borrows registry-derived admission-time capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[AuthorizedSkillCapability] {
        &self.capabilities
    }
}

impl fmt::Debug for AdmittedSkill {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmittedSkill([redacted])")
    }
}

/// Fail-closed Skills admission service.
pub struct SkillAdmissionService<V, T, R, P> {
    extension_policy: SkillsExtensionPolicy,
    signature_verifier: V,
    trust_store: T,
    revocations: R,
    principal_policy: P,
}

impl<V, T, R, P> SkillAdmissionService<V, T, R, P>
where
    V: ManifestSignatureVerifier,
    T: SkillTrustStore,
    R: SkillRevocationRepository,
    P: SkillPrincipalPolicy,
{
    /// Creates an admission service around explicit extension, trust, and policy boundaries.
    #[must_use]
    pub const fn new(
        extension_policy: SkillsExtensionPolicy,
        signature_verifier: V,
        trust_store: T,
        revocations: R,
        principal_policy: P,
    ) -> Self {
        Self {
            extension_policy,
            signature_verifier,
            trust_store,
            revocations,
            principal_policy,
        }
    }

    /// Admits a signed Skill for one canonical, exactly negotiated MCP request.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when negotiation or canonical binding fails; the signed manifest,
    /// inventory, or isolation profile is invalid or executable; signature, trust, or revocation
    /// checks fail; or current registry and principal policy deny a requested capability.
    pub fn admit(
        &self,
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        registry: &CapabilityRegistry,
        signed: SignedSkillManifest,
    ) -> Result<AdmittedSkill, AdmissionError> {
        self.extension_policy.require_skills(request)?;
        let binding = SkillBinding::from_request(server, request)?;
        let canonical = serde_json::to_vec(&signed.payload)
            .map_err(|_| AdmissionError::InvalidManifestEncoding)?;
        if canonical.len() > MAX_SKILL_MANIFEST_BYTES {
            return Err(AdmissionError::ManifestTooLarge);
        }
        if signed.algorithm != "Ed25519"
            || !is_identifier(&signed.key_id)
            || signed.signature.is_empty()
            || signed.signature.len() > 256
            || !signed.signature.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(AdmissionError::InvalidSignature);
        }
        self.signature_verifier
            .verify(
                &signed.key_id,
                &signed.algorithm,
                &canonical,
                &signed.signature,
            )
            .map_err(|_| AdmissionError::InvalidSignature)?;
        validate_manifest(&signed.payload, server.server_id())?;
        let provenance = SkillProvenance {
            signer_key_id: signed.key_id,
            signature_algorithm: signed.algorithm,
            signature: signed.signature,
            manifest_digest: sha256_digest(&canonical),
        };
        let skill_uri = signed.payload.uri.as_str();
        let trust = self
            .trust_store
            .signer_status(&binding, provenance.signer_key_id(), skill_uri)
            .map_err(|_| AdmissionError::TrustUnavailable)?;
        if trust != TrustStatus::Trusted {
            return Err(AdmissionError::Untrusted);
        }
        let revocation = self
            .revocations
            .status(
                &binding,
                skill_uri,
                &signed.payload.version,
                &signed.payload.package_digest,
                &provenance,
            )
            .map_err(|_| AdmissionError::RevocationUnavailable)?;
        if revocation != RevocationStatus::Active {
            return Err(AdmissionError::Revoked);
        }
        let capabilities = authorize_capabilities(
            registry,
            &self.principal_policy,
            request,
            server,
            &signed.payload.capabilities,
        )?;
        Ok(AdmittedSkill {
            binding,
            provenance,
            manifest: signed.payload,
            capabilities,
        })
    }
}

/// Admission rejection without manifest content, token, credential, tenant, or principal details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdmissionError {
    /// Exact request-scoped Skills negotiation or explicit server enablement failed.
    #[error("MCP Skills negotiation failed")]
    Negotiation,
    /// Canonical tenant, principal, server, or installation binding was absent or invalid.
    #[error("invalid Skill admission context")]
    InvalidContext,
    /// Canonical signed payload encoding failed.
    #[error("invalid Skill manifest encoding")]
    InvalidManifestEncoding,
    /// Signed manifest exceeded its hard byte bound.
    #[error("Skill manifest exceeds size bound")]
    ManifestTooLarge,
    /// Signature metadata or verification failed.
    #[error("invalid Skill manifest signature")]
    InvalidSignature,
    /// Version, identity, URI, metadata, capability, or extension fields were invalid.
    #[error("invalid Skill manifest")]
    InvalidManifest,
    /// Inventory violated path, symlink, size, or integrity policy.
    #[error("invalid Skill package inventory")]
    InvalidInventory,
    /// Executable content was declared, but no enforced executor or sandbox exists.
    #[error("Skill execution is unsupported; executable content is not sandboxed")]
    ExecutionUnsupported,
    /// Data-only profile exposed ambient authority or exceeded hard limits.
    #[error("invalid Skill data-only isolation profile")]
    InvalidIsolation,
    /// Trust store was unavailable; admission fails closed.
    #[error("Skill trust decision unavailable")]
    TrustUnavailable,
    /// Signer is not trusted for the canonical binding and Skill.
    #[error("Skill signer is untrusted")]
    Untrusted,
    /// Revocation state was unavailable; admission fails closed.
    #[error("Skill revocation decision unavailable")]
    RevocationUnavailable,
    /// Signer, Skill version, provenance, or package is revoked.
    #[error("Skill is revoked")]
    Revoked,
    /// Registry or current principal/server policy denied a declared request.
    #[error("Skill capability request denied")]
    CapabilityDenied,
}

impl From<crate::negotiation::NegotiationError> for AdmissionError {
    fn from(_: crate::negotiation::NegotiationError) -> Self {
        Self::Negotiation
    }
}

impl From<BindingError> for AdmissionError {
    fn from(_: BindingError) -> Self {
        Self::InvalidContext
    }
}

impl From<InventoryError> for AdmissionError {
    fn from(error: InventoryError) -> Self {
        match error {
            InventoryError::ExecutionUnsupported => Self::ExecutionUnsupported,
            InventoryError::Bounds
            | InventoryError::InvalidPath
            | InventoryError::SymbolicLink
            | InventoryError::InvalidIntegrity
            | InventoryError::InvalidInstructions => Self::InvalidInventory,
        }
    }
}

impl From<IsolationError> for AdmissionError {
    fn from(error: IsolationError) -> Self {
        match error {
            IsolationError::ExecutionUnsupported => Self::ExecutionUnsupported,
            IsolationError::NotLeastPrivilege => Self::InvalidIsolation,
        }
    }
}

impl From<CapabilityAuthorizationError> for AdmissionError {
    fn from(_: CapabilityAuthorizationError) -> Self {
        Self::CapabilityDenied
    }
}

/// Re-resolves effective capability grants from the immutable registry and current request policy.
///
/// This function never trusts a manifest, package, instruction, or retained admission grant as an
/// authority. Exact registry revision, runtime availability, exposure, tenant mode, canonical
/// authorization, and deployment policy are checked on every call.
///
/// # Errors
///
/// Returns [`CapabilityAuthorizationError`] when canonical authorization is denied; a requested
/// capability revision is missing, unavailable, invalid, or incompatible with the requested
/// exposure or tenant mode; or current principal policy denies it or exceeds permission bounds.
pub fn authorize_capabilities(
    registry: &CapabilityRegistry,
    policy: &impl SkillPrincipalPolicy,
    request: &McpRequestContext,
    server: &SkillServerIdentity,
    requested: &[CapabilityRequest],
) -> Result<Vec<AuthorizedSkillCapability>, CapabilityAuthorizationError> {
    if request.canonical().invocation().authorization() != Decision::Allow {
        return Err(CapabilityAuthorizationError);
    }
    let mut authorized = Vec::with_capacity(requested.len());
    for request_ceiling in requested {
        let document = registry
            .document(&request_ceiling.key)
            .ok_or(CapabilityAuthorizationError)?;
        if document.key() != request_ceiling.key
            || !registry
                .availability(&request_ceiling.key)
                .runtime()
                .is_available()
            || document
                .exposures
                .binary_search(&request_ceiling.exposure.registry_exposure())
                .is_err()
            || document
                .tenant_modes
                .binary_search(&request.canonical().tenant_mode())
                .is_err()
        {
            return Err(CapabilityAuthorizationError);
        }
        document
            .validate()
            .map_err(|_| CapabilityAuthorizationError)?;
        let policy_permissions =
            policy.allowed_permissions(request, server, document, request_ceiling.exposure)?;
        if policy_permissions.len() > MAX_PERMISSIONS {
            return Err(CapabilityAuthorizationError);
        }
        let permissions = request_ceiling
            .permissions
            .iter()
            .filter(|permission| {
                document.permissions.binary_search(permission).is_ok()
                    && policy_permissions.contains(*permission)
            })
            .cloned()
            .collect();
        authorized.push(AuthorizedSkillCapability {
            key: document.key(),
            exposure: request_ceiling.exposure,
            permissions,
            data_policy: request.canonical().invocation().data_policy().clone(),
        });
    }
    Ok(authorized)
}

fn validate_manifest(manifest: &SkillManifest, server_id: &str) -> Result<(), AdmissionError> {
    if manifest.extension_revision != SKILLS_EXTENSION_REVISION
        || !is_identifier(server_id)
        || !is_identifier(&manifest.skill_id)
        || !is_semver(&manifest.version)
        || manifest.name.is_empty()
        || manifest.name.len() > 128
        || manifest.description.is_empty()
        || manifest.description.len() > 2_048
        || !valid_skill_uri(
            &manifest.uri,
            server_id,
            &manifest.skill_id,
            &manifest.version,
        )
        || !frontmatter_matches(manifest)
        || !valid_capabilities(&manifest.capabilities)
        || !valid_unknown_fields(&manifest.unknown_fields)
        || !valid_untrusted_metadata(manifest)
    {
        return Err(AdmissionError::InvalidManifest);
    }
    manifest.execution.validate()?;
    validate_inventory(
        &manifest.inventory,
        &manifest.package_digest,
        &manifest.execution,
    )?;
    if declared_executable_formats(manifest) != manifest.execution.process.executable_formats {
        return Err(AdmissionError::InvalidIsolation);
    }
    Ok(())
}

fn valid_skill_uri(uri: &Url, server_id: &str, skill_id: &str, version: &str) -> bool {
    if uri.scheme() != "skill"
        || uri.host_str() != Some(server_id)
        || uri.query().is_some()
        || uri.fragment().is_some()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
    {
        return false;
    }
    uri.path_segments().is_some_and(|mut segments| {
        segments.next() == Some(skill_id)
            && segments.next() == Some(version)
            && segments.next().is_none()
    })
}

fn frontmatter_matches(manifest: &SkillManifest) -> bool {
    let Value::Object(fields) = &manifest.frontmatter else {
        return false;
    };
    fields.get("name").and_then(Value::as_str) == Some(&manifest.name)
        && fields.get("description").and_then(Value::as_str) == Some(&manifest.description)
}

fn valid_capabilities(capabilities: &[CapabilityRequest]) -> bool {
    if capabilities.len() > MAX_SKILL_CAPABILITIES {
        return false;
    }
    let mut previous: Option<(&CapabilityKey, SkillExposure)> = None;
    for request in capabilities {
        let current = (&request.key, request.exposure);
        if previous.is_some_and(|previous| previous >= current)
            || request.permissions.len() > MAX_PERMISSIONS
            || !request.permissions.windows(2).all(|pair| pair[0] < pair[1])
        {
            return false;
        }
        previous = Some(current);
    }
    true
}

fn valid_unknown_fields(fields: &BTreeMap<String, Value>) -> bool {
    fields.len() <= MAX_EXTENSION_FIELDS
        && fields
            .keys()
            .all(|key| key.starts_with("x-") && is_identifier(key))
}

fn valid_untrusted_metadata(manifest: &SkillManifest) -> bool {
    let mut nodes = 0;
    if !validate_value(&manifest.frontmatter, 0, &mut nodes) {
        return false;
    }
    manifest
        .unknown_fields
        .values()
        .all(|value| validate_value(value, 0, &mut nodes))
}

fn validate_value(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    *nodes = match nodes.checked_add(1) {
        Some(nodes) => nodes,
        None => return false,
    };
    if depth > MAX_UNTRUSTED_VALUE_DEPTH || *nodes > MAX_UNTRUSTED_VALUE_NODES {
        return false;
    }
    match value {
        Value::Array(values) => values
            .iter()
            .all(|value| validate_value(value, depth + 1, nodes)),
        Value::Object(values) => values
            .iter()
            .all(|(key, value)| key.len() <= 256 && validate_value(value, depth + 1, nodes)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

pub(crate) fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
}

fn is_semver(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 64
        || value.bytes().filter(|byte| *byte == b'+').count() > 1
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return false;
    }
    let suffix_start = value
        .char_indices()
        .find_map(|(index, character)| matches!(character, '-' | '+').then_some(index));
    let core = suffix_start.map_or(value, |index| &value[..index]);
    if suffix_start.is_some_and(|index| value[index + 1..].split(['.', '+']).any(str::is_empty)) {
        return false;
    }
    let mut parts = core.split('.');
    let valid = (0..3).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    valid && parts.next().is_none()
}

/// Returns executable formats present in a signed inventory.
///
/// Any non-empty result is unsupported and must be rejected; it does not indicate sandbox support.
#[must_use]
pub fn declared_executable_formats(manifest: &SkillManifest) -> BTreeSet<ExecutableFormat> {
    manifest
        .inventory
        .iter()
        .filter_map(|entry| match entry.kind {
            crate::package::PackageFileKind::Executable { format } => Some(format),
            crate::package::PackageFileKind::Instructions
            | crate::package::PackageFileKind::Resource => None,
        })
        .collect()
}
