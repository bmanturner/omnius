use std::collections::{BTreeMap, BTreeSet};

use omnius_agent_capability_registry::{CapabilityKey, CapabilityRegistry, Exposure};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::negotiation::{APPS_EXTENSION_REVISION, require_apps};

/// Hard ceiling for an MCP App HTML resource.
pub const MAX_UI_RESOURCE_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum retained forward-compatible manifest fields.
pub const MAX_EXTENSION_FIELDS: usize = 32;
/// Maximum serialized bytes retained across forward-compatible manifest fields.
pub const MAX_EXTENSION_FIELD_BYTES: usize = 64 * 1024;
/// Required media type for Apps HTML resources.
pub const APP_HTML_MEDIA_TYPE: &str = "text/html;profile=mcp-app";

/// Maximum canonical signed App envelope bytes.
pub const MAX_UI_MANIFEST_BYTES: usize = 256 * 1024;
/// Domain separator prepended to every canonical App envelope before signing.
pub const UI_MANIFEST_SIGNATURE_DOMAIN: &str = "omnius.mcp-apps.ui-manifest.v1";

/// Canonical identity scope and immutable manifest protected by one signature.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiManifestEnvelope {
    /// Exact tenant, principal, server, and installation authorized by the signer.
    pub binding: AppBinding,
    /// Immutable UI manifest authorized only within `binding`.
    pub manifest: UiManifest,
}

impl UiManifestEnvelope {
    /// Creates the typed envelope that must be signed as one unit.
    #[must_use]
    pub const fn new(binding: AppBinding, manifest: UiManifest) -> Self {
        Self { binding, manifest }
    }

    /// Returns deterministic, domain-separated bytes for signing or verification.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidManifestEncoding`] if the typed envelope cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let value =
            serde_json::to_value(self).map_err(|_| ManifestError::InvalidManifestEncoding)?;
        let json = serde_json::to_vec(&canonicalize_json(value))
            .map_err(|_| ManifestError::InvalidManifestEncoding)?;
        let mut canonical = Vec::with_capacity(UI_MANIFEST_SIGNATURE_DOMAIN.len() + 1 + json.len());
        canonical.extend_from_slice(UI_MANIFEST_SIGNATURE_DOMAIN.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(&json);
        Ok(canonical)
    }
}

impl std::fmt::Debug for UiManifestEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UiManifestEnvelope([redacted])")
    }
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize_json(value)))
                    .collect(),
            )
        }
        value => value,
    }
}

/// Signed envelope for versioned Apps metadata.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUiManifest {
    /// Identifier for the verification key, never a credential.
    pub key_id: String,
    /// Signature algorithm. Only Ed25519 is admitted.
    pub algorithm: String,
    /// Detached signature encoded for the configured verifier.
    pub signature: String,
    /// Domain-separated canonical identity and manifest envelope.
    pub envelope: UiManifestEnvelope,
}

impl std::fmt::Debug for SignedUiManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignedUiManifest([redacted])")
    }
}

/// Signed, immutable UI resource declaration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiManifest {
    /// Extension schema revision.
    pub extension_version: String,
    /// Stable resource identifier.
    pub resource_id: String,
    /// Semantic resource version embedded in the resource URI.
    pub version: String,
    /// Immutable UI resource metadata.
    pub resource: UiResourceMetadata,
    /// Host-mediated message contracts exposed by this resource.
    #[serde(default)]
    pub messages: Vec<MessageContract>,
    /// Safely retained forward-compatible `x-` fields.
    #[serde(flatten)]
    pub unknown_fields: BTreeMap<String, Value>,
}

/// Integrity, origin, and sandbox metadata for one UI resource.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiResourceMetadata {
    /// Canonical `ui://server/installation/resource/version/digest` URI.
    pub uri: Url,
    /// Exact Apps HTML media type.
    pub media_type: String,
    /// Exact byte length in object storage.
    pub byte_len: u64,
    /// Lowercase `sha256:` digest of the stored bytes.
    pub digest: String,
    /// Dedicated HTTPS origin used to isolate the embedded resource.
    pub isolation_origin: Url,
    /// Deny-by-default CSP domain declaration.
    #[serde(default)]
    pub csp: CspPolicy,
    /// Exact iframe sandbox tokens requested by the App.
    pub sandbox: SandboxPolicy,
    /// Browser permission ceiling requested by the App; this never grants browser rights.
    #[serde(default)]
    pub permission_ceiling: BTreeSet<AppPermission>,
}

/// CSP origins declared by an App. Empty sets deny the corresponding access.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CspPolicy {
    /// Origins available to `connect-src`.
    #[serde(default)]
    pub connect_origins: BTreeSet<String>,
    /// Origins available to resource loading directives.
    #[serde(default)]
    pub resource_origins: BTreeSet<String>,
    /// Origins available to `frame-src`.
    #[serde(default)]
    pub frame_origins: BTreeSet<String>,
    /// Origins available to base URI resolution.
    #[serde(default)]
    pub base_uri_origins: BTreeSet<String>,
}

/// Explicit sandbox configuration. Its typed tokens exclude popups, navigation, and downloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    /// Allowed tokens. `allow-scripts` is required; `allow-same-origin` is optional.
    pub tokens: BTreeSet<SandboxToken>,
}

/// Sandbox tokens that are safe on a dedicated isolation origin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxToken {
    /// Allows the App code to run.
    AllowScripts,
    /// Preserves its dedicated, non-host origin.
    AllowSameOrigin,
}

/// Browser permissions that a manifest may narrowly request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppPermission {
    /// Clipboard read access.
    ClipboardRead,
    /// Clipboard write access.
    ClipboardWrite,
    /// Camera access.
    Camera,
    /// Microphone access.
    Microphone,
    /// Geolocation access.
    Geolocation,
}

/// Schema for one host-mediated App message action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageContract {
    /// Stable action name authorized separately for every message.
    pub action: String,
    /// Exact registry capability revision this action may request.
    ///
    /// This declaration is only a ceiling. Admission requires the exact key to exist in the
    /// immutable registry and execution still traverses every registry guardrail.
    pub capability: CapabilityKey,
    /// Maximum serialized payload size for the action.
    pub max_payload_bytes: usize,
    /// Fields accepted by the action.
    pub allowed_fields: BTreeSet<String>,
    /// Required fields, necessarily a subset of `allowed_fields`.
    #[serde(default)]
    pub required_fields: BTreeSet<String>,
}

/// Host ceiling and allowlists. A manifest can only narrow this policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSecurityPolicy {
    /// Maximum admitted resource bytes.
    pub max_resource_bytes: u64,
    /// HTTPS origin of the MCP host, forbidden as the App isolation origin.
    pub host_origin: String,
    /// Dedicated isolation origins the host can serve.
    pub isolation_origins: BTreeSet<String>,
    /// Maximum CSP domains accepted in each category.
    pub connect_origins: BTreeSet<String>,
    /// Maximum resource origins.
    pub resource_origins: BTreeSet<String>,
    /// Maximum frame origins.
    pub frame_origins: BTreeSet<String>,
    /// Maximum base URI origins.
    pub base_uri_origins: BTreeSet<String>,
    /// Maximum permission declaration accepted; actual grants remain an ordinary host decision.
    pub permission_ceiling: BTreeSet<AppPermission>,
}

/// Explicit client isolation support beyond exact request-scoped extension negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAppSupport {
    /// Whether the client provides a dedicated isolation origin.
    pub isolated_origin: bool,
    /// Whether the client validates and correlates host-mediated messages.
    pub host_messaging: bool,
}

/// Canonical tenant, principal, server, and installation scope of one admitted App.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppBinding {
    #[serde(rename = "tenant_id")]
    tenant: TenantId,
    #[serde(rename = "principal_id")]
    principal: SubjectId,
    #[serde(rename = "server_id")]
    server: String,
    #[serde(rename = "installation_id")]
    installation: String,
}

impl AppBinding {
    /// Derives canonical identity from a freshly negotiated MCP request and binds host identities.
    ///
    /// # Errors
    ///
    /// Returns a redacted error unless Apps was negotiated exactly, a tenant is present, and both
    /// host identifiers satisfy the bounded identifier grammar.
    pub fn from_request(
        context: &McpRequestContext,
        server_id: impl Into<String>,
        installation_id: impl Into<String>,
    ) -> Result<Self, ManifestError> {
        require_apps(context)?;
        let server_id = server_id.into();
        let installation_id = installation_id.into();
        let invocation = context.canonical().invocation();
        if invocation.authorization() != Decision::Allow {
            return Err(ManifestError::ContextMismatch);
        }
        let tenant_id = invocation
            .tenant_id()
            .ok_or(ManifestError::ContextMismatch)?;
        if !is_uri_host_identifier(&server_id) || !is_uri_segment_identifier(&installation_id) {
            return Err(ManifestError::ContextMismatch);
        }
        Ok(Self {
            tenant: tenant_id,
            principal: invocation.principal().subject_id,
            server: server_id,
            installation: installation_id,
        })
    }

    /// Requires this scope to match a freshly negotiated request and exact host identities.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::ContextMismatch`] unless Apps is negotiated and the canonical
    /// tenant, principal, server, and installation identities all match this binding.
    pub fn require_request(
        &self,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
    ) -> Result<(), ManifestError> {
        require_apps(context)?;
        let invocation = context.canonical().invocation();
        if invocation.tenant_id() != Some(self.tenant)
            || invocation.principal().subject_id != self.principal
            || self.server != server_id
            || self.installation != installation_id
        {
            return Err(ManifestError::ContextMismatch);
        }
        Ok(())
    }

    /// Returns the canonical tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }

    /// Returns the canonical principal identity.
    #[must_use]
    pub const fn principal_id(&self) -> SubjectId {
        self.principal
    }

    /// Returns the bound MCP server identity.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server
    }

    /// Returns the bound installation identity.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation
    }
}

impl std::fmt::Debug for AppBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AppBinding([redacted])")
    }
}

/// Verification boundary implemented by the deployment trust service.
pub trait ManifestSignatureVerifier {
    /// Verifies a detached signature over the exact domain-separated canonical envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureVerificationError`] when the key, algorithm, payload, or detached
    /// signature does not satisfy the deployment trust policy.
    fn verify(
        &self,
        key_id: &str,
        algorithm: &str,
        signed_payload: &[u8],
        signature: &str,
    ) -> Result<(), SignatureVerificationError>;
}

/// Non-sensitive signature failure returned by a trust adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("manifest signature verification failed")]
pub struct SignatureVerificationError;

/// A manifest that passed exact negotiation, registry, identity, signature, and policy admission.
#[derive(Clone, PartialEq)]
pub struct AdmittedUiManifest {
    manifest: UiManifest,
    signer_key_id: String,
    manifest_digest: String,
    binding: AppBinding,
    capability_keys: BTreeSet<CapabilityKey>,
}

impl std::fmt::Debug for AdmittedUiManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdmittedUiManifest([redacted])")
    }
}

impl AdmittedUiManifest {
    /// Returns the admitted manifest.
    #[must_use]
    pub const fn manifest(&self) -> &UiManifest {
        &self.manifest
    }

    /// Returns the non-secret signer key identifier verified during admission.
    #[must_use]
    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    /// Returns the digest of the canonical signed envelope.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Returns the canonical scope captured at admission.
    #[must_use]
    pub const fn binding(&self) -> &AppBinding {
        &self.binding
    }

    /// Returns the exact registry capability revisions declared as action ceilings.
    #[must_use]
    pub const fn capability_keys(&self) -> &BTreeSet<CapabilityKey> {
        &self.capability_keys
    }

    /// Renders the deny-by-default CSP only for the same freshly negotiated identity scope.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::ContextMismatch`] unless the fresh canonical request is
    /// authorized and exactly matches the tenant, principal, server, and installation binding.
    pub fn content_security_policy(
        &self,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
    ) -> Result<String, ManifestError> {
        self.binding
            .require_request(context, server_id, installation_id)?;
        if context.canonical().invocation().authorization() != Decision::Allow {
            return Err(ManifestError::ContextMismatch);
        }
        let csp = &self.manifest.resource.csp;
        let mut policy = String::from(
            "default-src 'none'; object-src 'none'; script-src 'self'; style-src 'self'",
        );
        append_csp_origins(&mut policy, "connect-src", &csp.connect_origins, false);
        append_csp_origins(&mut policy, "img-src", &csp.resource_origins, true);
        append_csp_origins(&mut policy, "font-src", &csp.resource_origins, true);
        append_csp_origins(&mut policy, "media-src", &csp.resource_origins, true);
        append_csp_origins(&mut policy, "frame-src", &csp.frame_origins, false);
        append_csp_origins(&mut policy, "base-uri", &csp.base_uri_origins, false);
        Ok(policy)
    }
}

/// Fail-closed Apps manifest admission service.
pub struct UiManifestAdmission<V> {
    signature_verifier: V,
    host_policy: HostSecurityPolicy,
}

impl<V> UiManifestAdmission<V>
where
    V: ManifestSignatureVerifier,
{
    /// Creates an admission service around deployment-provided trust and host policy.
    #[must_use]
    pub const fn new(signature_verifier: V, host_policy: HostSecurityPolicy) -> Self {
        Self {
            signature_verifier,
            host_policy,
        }
    }

    /// Admits a signed UI manifest for one exact negotiated and canonical identity scope.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when exact negotiation, identity binding, client isolation,
    /// canonical encoding, signature verification, host policy, or registry admission fails.
    pub fn admit(
        &self,
        registry: &CapabilityRegistry,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
        client: &ClientAppSupport,
        signed: SignedUiManifest,
    ) -> Result<AdmittedUiManifest, ManifestError> {
        let binding = AppBinding::from_request(context, server_id, installation_id)?;
        validate_client_support(client)?;
        if signed.algorithm != "Ed25519"
            || !is_identifier(&signed.key_id)
            || signed.signature.is_empty()
            || signed.signature.len() > 256
        {
            return Err(ManifestError::InvalidSignature);
        }
        if signed.envelope.binding != binding {
            return Err(ManifestError::ContextMismatch);
        }
        let signed_payload = signed.envelope.canonical_bytes()?;
        if signed_payload.len() > MAX_UI_MANIFEST_BYTES {
            return Err(ManifestError::ManifestTooLarge);
        }
        self.signature_verifier
            .verify(
                &signed.key_id,
                &signed.algorithm,
                &signed_payload,
                &signed.signature,
            )
            .map_err(|_| ManifestError::InvalidSignature)?;
        validate_manifest(
            &signed.envelope.manifest,
            &binding,
            &self.host_policy,
            registry,
        )?;
        let capability_keys = signed
            .envelope
            .manifest
            .messages
            .iter()
            .map(|contract| contract.capability.clone())
            .collect();
        Ok(AdmittedUiManifest {
            manifest_digest: crate::resource::sha256_digest(&signed_payload),
            signer_key_id: signed.key_id,
            manifest: signed.envelope.manifest,
            binding,
            capability_keys,
        })
    }
}

/// Apps manifest rejection without attacker-controlled or credential-bearing details.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ManifestError {
    /// Per-request extension negotiation failed.
    #[error("MCP Apps negotiation failed")]
    Negotiation,
    /// The request identity or server/installation scope did not match admission.
    #[error("MCP App identity scope mismatch")]
    ContextMismatch,
    /// Client lacks a mandatory Apps isolation feature or uses another revision.
    #[error("client does not support the required MCP Apps isolation contract")]
    ClientUnsupported,
    /// Signature metadata or verification failed.
    #[error("invalid MCP App manifest signature")]
    InvalidSignature,
    /// Signed payload could not be encoded canonically.
    #[error("invalid MCP App manifest encoding")]
    InvalidManifestEncoding,
    /// Signed manifest exceeded its hard byte bound.
    #[error("MCP App manifest exceeds size bound")]
    ManifestTooLarge,
    /// Extension or resource version is unsupported or malformed.
    #[error("invalid MCP App version")]
    InvalidVersion,
    /// Resource identity or URI is malformed or mutable.
    #[error("invalid MCP App resource identity")]
    InvalidResource,
    /// Resource size, media type, or digest declaration is invalid.
    #[error("invalid MCP App resource integrity metadata")]
    InvalidIntegrity,
    /// Origin or CSP declaration exceeds host policy.
    #[error("MCP App origin or CSP denied")]
    CspDenied,
    /// Sandbox declaration is not the required strict profile.
    #[error("MCP App sandbox denied")]
    SandboxDenied,
    /// Requested browser permission exceeds host policy.
    #[error("MCP App permission denied")]
    PermissionDenied,
    /// Host-mediated message contract is malformed or ambiguous.
    #[error("invalid MCP App message contract")]
    InvalidMessageContract,
    /// A declared capability key was absent, stale, or not browser-exposed in the registry.
    #[error("MCP App capability declaration denied by registry")]
    RegistryDenied,
    /// Forward-compatible metadata is unsafe or exceeds retention bounds.
    #[error("invalid MCP App extension metadata")]
    InvalidExtensionMetadata,
}

impl From<crate::negotiation::AppsNegotiationError> for ManifestError {
    fn from(_: crate::negotiation::AppsNegotiationError) -> Self {
        Self::Negotiation
    }
}

pub(crate) fn validate_client_support(client: &ClientAppSupport) -> Result<(), ManifestError> {
    if !client.isolated_origin || !client.host_messaging {
        return Err(ManifestError::ClientUnsupported);
    }
    Ok(())
}

fn validate_manifest(
    manifest: &UiManifest,
    binding: &AppBinding,
    host_policy: &HostSecurityPolicy,
    registry: &CapabilityRegistry,
) -> Result<(), ManifestError> {
    if manifest.extension_version != APPS_EXTENSION_REVISION || !is_semver(&manifest.version) {
        return Err(ManifestError::InvalidVersion);
    }
    if !is_uri_segment_identifier(&manifest.resource_id) {
        return Err(ManifestError::InvalidResource);
    }
    validate_resource(
        &manifest.resource,
        binding,
        &manifest.resource_id,
        &manifest.version,
        host_policy,
    )?;
    validate_messages(&manifest.messages, registry)?;
    validate_unknown_fields(&manifest.unknown_fields)?;
    Ok(())
}

fn validate_resource(
    resource: &UiResourceMetadata,
    binding: &AppBinding,
    resource_id: &str,
    version: &str,
    host_policy: &HostSecurityPolicy,
) -> Result<(), ManifestError> {
    if resource.media_type != APP_HTML_MEDIA_TYPE
        || resource.byte_len == 0
        || resource.byte_len > MAX_UI_RESOURCE_BYTES
        || resource.byte_len > host_policy.max_resource_bytes
        || !is_sha256_digest(&resource.digest)
    {
        return Err(ManifestError::InvalidIntegrity);
    }
    if resource.uri.path().contains('%') {
        return Err(ManifestError::InvalidResource);
    }
    let canonical = canonical_resource_uri(binding, resource_id, version, &resource.digest)?;
    if resource.uri != canonical || resource.uri.as_str() != canonical.as_str() {
        return Err(ManifestError::InvalidResource);
    }
    let isolation_origin =
        strict_https_origin(&resource.isolation_origin).ok_or(ManifestError::CspDenied)?;
    let host_origin =
        parse_strict_origin(&host_policy.host_origin).ok_or(ManifestError::CspDenied)?;
    if isolation_origin == host_origin || !host_policy.isolation_origins.contains(&isolation_origin)
    {
        return Err(ManifestError::CspDenied);
    }
    validate_csp(&resource.csp, host_policy)?;
    if !resource
        .sandbox
        .tokens
        .contains(&SandboxToken::AllowScripts)
    {
        return Err(ManifestError::SandboxDenied);
    }
    if !resource
        .permission_ceiling
        .is_subset(&host_policy.permission_ceiling)
    {
        return Err(ManifestError::PermissionDenied);
    }
    Ok(())
}

fn validate_csp(csp: &CspPolicy, host: &HostSecurityPolicy) -> Result<(), ManifestError> {
    validate_origin_subset(&csp.connect_origins, &host.connect_origins)?;
    validate_origin_subset(&csp.resource_origins, &host.resource_origins)?;
    validate_origin_subset(&csp.frame_origins, &host.frame_origins)?;
    validate_origin_subset(&csp.base_uri_origins, &host.base_uri_origins)?;
    Ok(())
}

fn validate_origin_subset(
    requested: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
) -> Result<(), ManifestError> {
    if !requested.is_subset(allowed)
        || requested
            .iter()
            .any(|origin| parse_strict_origin(origin).is_none())
    {
        return Err(ManifestError::CspDenied);
    }
    Ok(())
}

fn validate_messages(
    messages: &[MessageContract],
    registry: &CapabilityRegistry,
) -> Result<(), ManifestError> {
    let mut actions = BTreeSet::new();
    for message in messages {
        if !is_identifier(&message.action)
            || message.max_payload_bytes == 0
            || message.max_payload_bytes > 64 * 1024
            || !message.required_fields.is_subset(&message.allowed_fields)
            || message
                .allowed_fields
                .iter()
                .any(|field| !is_identifier(field) || is_sensitive_name(field))
            || !actions.insert(&message.action)
        {
            return Err(ManifestError::InvalidMessageContract);
        }
        let document = registry
            .document(&message.capability)
            .ok_or(ManifestError::RegistryDenied)?;
        if document.deprecated
            || document
                .exposures
                .binary_search(&Exposure::Browser)
                .is_err()
        {
            return Err(ManifestError::RegistryDenied);
        }
    }
    Ok(())
}

fn validate_unknown_fields(fields: &BTreeMap<String, Value>) -> Result<(), ManifestError> {
    if fields.len() > MAX_EXTENSION_FIELDS
        || fields
            .keys()
            .any(|key| !key.starts_with("x-") || !is_identifier(key))
    {
        return Err(ManifestError::InvalidExtensionMetadata);
    }
    let encoded =
        serde_json::to_vec(fields).map_err(|_| ManifestError::InvalidExtensionMetadata)?;
    if encoded.len() > MAX_EXTENSION_FIELD_BYTES {
        return Err(ManifestError::InvalidExtensionMetadata);
    }
    Ok(())
}

fn append_csp_origins(
    policy: &mut String,
    directive: &str,
    origins: &BTreeSet<String>,
    include_self: bool,
) {
    policy.push_str("; ");
    policy.push_str(directive);
    if include_self {
        policy.push_str(" 'self'");
    }
    if origins.is_empty() && !include_self {
        policy.push_str(" 'none'");
    } else {
        for origin in origins {
            policy.push(' ');
            policy.push_str(origin);
        }
    }
}

fn strict_https_origin(url: &Url) -> Option<String> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_owned())
}

/// Builds the sole canonical App resource URI from exact decoded identity and integrity segments.
///
/// # Errors
///
/// Returns [`ManifestError::InvalidResource`] unless every component satisfies the canonical
/// decoded-segment grammar and the digest is a lowercase SHA-256 content address.
pub fn canonical_resource_uri(
    binding: &AppBinding,
    resource_id: &str,
    version: &str,
    digest: &str,
) -> Result<Url, ManifestError> {
    if !is_uri_host_identifier(binding.server_id())
        || !is_uri_segment_identifier(binding.installation_id())
        || !is_uri_segment_identifier(resource_id)
        || !is_semver(version)
        || !is_sha256_digest(digest)
    {
        return Err(ManifestError::InvalidResource);
    }
    let canonical = format!(
        "ui://{}/{}/{}/{}/{}",
        binding.server_id(),
        binding.installation_id(),
        resource_id,
        version,
        digest
    );
    let parsed = Url::parse(&canonical).map_err(|_| ManifestError::InvalidResource)?;
    if parsed.as_str() != canonical || parsed.host_str() != Some(binding.server_id()) {
        return Err(ManifestError::InvalidResource);
    }
    Ok(parsed)
}

fn is_uri_host_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !value.contains("..")
}

pub(crate) fn is_uri_segment_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn parse_strict_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    let normalized = strict_https_origin(&url)?;
    (normalized == value.trim_end_matches('/')).then_some(normalized)
}

pub(crate) fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
}

pub(crate) fn is_sensitive_name(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

pub(crate) fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
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
