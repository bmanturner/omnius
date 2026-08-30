use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use omnius_agent_capability_registry::TenantMode;
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::de::{self, DeserializeSeed as _, Visitor};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Absolute maximum encoded `_meta` object size accepted by this crate.
pub const HARD_MAX_METADATA_BYTES: usize = 65_536;
/// Absolute maximum JSON value depth accepted by this crate.
pub const HARD_MAX_METADATA_DEPTH: usize = 16;
/// Absolute maximum total object-key count accepted by this crate.
pub const HARD_MAX_METADATA_KEYS: usize = 256;
/// Absolute maximum UTF-8 bytes in any metadata key or string value.
pub const HARD_MAX_METADATA_STRING_BYTES: usize = 8_192;
/// Absolute maximum lifetime of one authorized metadata snapshot.
pub const HARD_MAX_SNAPSHOT_TTL_SECONDS: u64 = 300;

const MAX_REGISTERED_KEYS: usize = 128;
const MAX_KEY_BYTES: usize = 128;
const MAX_OWNER_BYTES: usize = 96;
const FINGERPRINT_DOMAIN: &[u8] = b"omnius.mcp-card.authorized-set.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"omnius.mcp-card.snapshot-evidence.v1\0";
const REGISTRY_DOMAIN: &[u8] = b"omnius.mcp-card.metadata-registry.v1\0";

/// Strict parsing and mutation limits for one `_meta` object.
// The shared `max_` prefix keeps each independently bounded dimension explicit at use sites.
#[expect(
    clippy::struct_field_names,
    reason = "each limit is an explicit maximum"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataLimits {
    max_bytes: usize,
    max_depth: usize,
    max_keys: usize,
    max_string_bytes: usize,
}

impl MetadataLimits {
    /// Creates limits that cannot exceed the crate's hard safety ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::InvalidLimits`] for a zero or excessive limit.
    pub fn try_new(
        max_bytes: usize,
        max_depth: usize,
        max_keys: usize,
        max_string_bytes: usize,
    ) -> Result<Self, MetadataError> {
        if max_bytes == 0
            || max_bytes > HARD_MAX_METADATA_BYTES
            || max_depth == 0
            || max_depth > HARD_MAX_METADATA_DEPTH
            || max_keys == 0
            || max_keys > HARD_MAX_METADATA_KEYS
            || max_string_bytes == 0
            || max_string_bytes > HARD_MAX_METADATA_STRING_BYTES
        {
            return Err(MetadataError::InvalidLimits);
        }
        Ok(Self {
            max_bytes,
            max_depth,
            max_keys,
            max_string_bytes,
        })
    }
}

impl Default for MetadataLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16_384,
            max_depth: 8,
            max_keys: 64,
            max_string_bytes: 4_096,
        }
    }
}

/// A validated, namespaced metadata key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MetadataKey(String);

impl MetadataKey {
    /// Validates a registered key. Registered keys must be ASCII and namespace-qualified.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::InvalidKey`] for an unqualified, malformed, or oversized key.
    pub fn parse(value: impl Into<String>) -> Result<Self, MetadataError> {
        let value = value.into();
        let qualified = value.contains('/') || value.contains('.');
        if value.is_empty()
            || value.len() > MAX_KEY_BYTES
            || !qualified
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
            })
        {
            return Err(MetadataError::InvalidKey);
        }
        Ok(Self(value))
    }

    /// Returns the canonical registered key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetadataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated module or adapter owner for registered metadata.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MetadataOwner(String);

impl MetadataOwner {
    /// Validates an ownership identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::InvalidOwner`] for a malformed or oversized owner.
    pub fn parse(value: impl Into<String>) -> Result<Self, MetadataError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OWNER_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
            })
        {
            return Err(MetadataError::InvalidOwner);
        }
        Ok(Self(value))
    }

    /// Returns the canonical ownership identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inclusive server support declaration for metadata versions.
///
/// Request activation never uses range matching: [`MetadataAccessPolicy`] requires one exact
/// version and resolution requires equality with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataVersionRange {
    minimum: u16,
    maximum: u16,
}

impl MetadataVersionRange {
    /// Creates a non-zero inclusive server support declaration.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::InvalidVersionRange`] for zero or inverted bounds.
    pub fn try_new(minimum: u16, maximum: u16) -> Result<Self, MetadataError> {
        if minimum == 0 || maximum < minimum {
            return Err(MetadataError::InvalidVersionRange);
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns the lowest server-supported metadata version.
    #[must_use]
    pub const fn minimum(self) -> u16 {
        self.minimum
    }

    /// Returns the highest server-supported metadata version.
    #[must_use]
    pub const fn maximum(self) -> u16 {
        self.maximum
    }

    const fn contains(self, version: u16) -> bool {
        version >= self.minimum && version <= self.maximum
    }
}

/// Compatibility lifecycle for one registered metadata key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataLifecycle {
    /// Explicit experimental access is required before the value may be projected.
    Preview,
    /// The exact version is supported without an experimental metadata-key opt-in.
    Stable,
    /// Compatibility is retained only when policy explicitly permits deprecated metadata.
    Deprecated,
    /// The key is retained internally but can never enter a public snapshot.
    Removed,
}

impl MetadataLifecycle {
    const fn fingerprint_code(self) -> u8 {
        match self {
            Self::Preview => 1,
            Self::Stable => 2,
            Self::Deprecated => 3,
            Self::Removed => 4,
        }
    }
}

/// Ownership and server-support declaration for one metadata key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataRegistration {
    key: MetadataKey,
    owner: MetadataOwner,
    versions: MetadataVersionRange,
    lifecycle: MetadataLifecycle,
}

impl MetadataRegistration {
    /// Creates a metadata-key registration.
    #[must_use]
    pub const fn new(
        key: MetadataKey,
        owner: MetadataOwner,
        versions: MetadataVersionRange,
        lifecycle: MetadataLifecycle,
    ) -> Self {
        Self {
            key,
            owner,
            versions,
            lifecycle,
        }
    }

    /// Returns the registered key.
    #[must_use]
    pub const fn key(&self) -> &MetadataKey {
        &self.key
    }

    /// Returns the sole module or adapter allowed to emit this key.
    #[must_use]
    pub const fn owner(&self) -> &MetadataOwner {
        &self.owner
    }

    /// Returns the server support declaration; request selection remains exact.
    #[must_use]
    pub const fn supported_versions(&self) -> MetadataVersionRange {
        self.versions
    }

    /// Returns the compatibility lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> MetadataLifecycle {
        self.lifecycle
    }
}

/// Positive bounded lifetime for one immutable authorized snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataSnapshotTtl(Duration);

impl MetadataSnapshotTtl {
    /// Creates a positive lifetime no greater than five minutes.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::InvalidSnapshotTtl`] for zero or excessive values.
    pub const fn from_seconds(seconds: u64) -> Result<Self, MetadataError> {
        if seconds == 0 || seconds > HARD_MAX_SNAPSHOT_TTL_SECONDS {
            return Err(MetadataError::InvalidSnapshotTtl);
        }
        Ok(Self(Duration::from_secs(seconds)))
    }

    const fn as_seconds(self) -> u64 {
        self.0.as_secs()
    }
}

/// Collision-free metadata-key ownership declarations and the sole snapshot authority.
#[derive(Clone, Debug)]
pub struct MetadataKeyRegistry {
    registrations: BTreeMap<MetadataKey, MetadataRegistration>,
    fingerprint: [u8; 32],
}

impl Default for MetadataKeyRegistry {
    fn default() -> Self {
        let registrations = BTreeMap::new();
        let fingerprint = registry_fingerprint(&registrations);
        Self {
            registrations,
            fingerprint,
        }
    }
}

impl MetadataKeyRegistry {
    /// Builds a bounded immutable ownership registry and rejects duplicate key claims.
    ///
    /// # Errors
    ///
    /// Returns a redacted registry validation error for excessive or duplicate declarations.
    pub fn try_new(
        registrations: impl IntoIterator<Item = MetadataRegistration>,
    ) -> Result<Self, MetadataError> {
        let mut values = BTreeMap::new();
        for registration in registrations {
            if values.len() >= MAX_REGISTERED_KEYS {
                return Err(MetadataError::TooManyRegistrations);
            }
            if values
                .insert(registration.key.clone(), registration)
                .is_some()
            {
                return Err(MetadataError::KeyOwnershipCollision);
            }
        }
        let fingerprint = registry_fingerprint(&values);
        Ok(Self {
            registrations: values,
            fingerprint,
        })
    }

    /// Returns the ownership declaration for a key, when registered.
    #[must_use]
    pub fn registration(&self, key: &MetadataKey) -> Option<&MetadataRegistration> {
        self.registrations.get(key)
    }

    /// Inserts a registered value only for its declared owner and canonical request context.
    ///
    /// Owner, exact version, principal, tenant, request, policy, and scope provenance remains
    /// private in memory. It is deliberately discarded by internal JSON forwarding.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an unregistered key, wrong owner, unsupported version,
    /// denied canonical context, collision, or metadata budget violation.
    pub fn insert_owned(
        &self,
        document: &mut MetaDocument,
        owner: &MetadataOwner,
        key: &MetadataKey,
        value: VersionedMetadataValue,
        request: &McpRequestContext,
    ) -> Result<(), MetadataError> {
        let provenance = self.provenance(owner, key, value.version, request)?;
        document.insert_bounded(key.as_str(), value.into_json())?;
        document.owned_keys.insert(key.clone(), provenance);
        Ok(())
    }

    /// Replaces one retained untrusted registered-looking value with a newly trusted value.
    ///
    /// This is the only path by which a parsed or forwarded registered key can regain meaning.
    /// The retained value itself is never trusted: the registered owner must supply a replacement
    /// exact-version value under the current canonical context. Already-owned values cannot be
    /// replaced through this method.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for a missing or already-owned retained key, an unregistered key,
    /// wrong owner, unsupported version, denied context, or metadata budget violation.
    pub fn reestablish_owned(
        &self,
        document: &mut MetaDocument,
        owner: &MetadataOwner,
        key: &MetadataKey,
        value: VersionedMetadataValue,
        request: &McpRequestContext,
    ) -> Result<(), MetadataError> {
        if !document.values.contains_key(key.as_str()) {
            return Err(MetadataError::MissingRetainedKey);
        }
        if document.owned_keys.contains_key(key) {
            return Err(MetadataError::KeyCollision);
        }
        let provenance = self.provenance(owner, key, value.version, request)?;
        document.replace_bounded(key.as_str(), value.into_json())?;
        document.owned_keys.insert(key.clone(), provenance);
        Ok(())
    }

    fn provenance(
        &self,
        owner: &MetadataOwner,
        key: &MetadataKey,
        version: u16,
        request: &McpRequestContext,
    ) -> Result<MetadataProvenance, MetadataError> {
        if request.canonical().invocation().authorization() != Decision::Allow {
            return Err(MetadataError::UnauthorizedContext);
        }
        let registration = self
            .registrations
            .get(key)
            .ok_or(MetadataError::UnregisteredKey)?;
        if registration.owner != *owner {
            return Err(MetadataError::WrongOwner);
        }
        if !registration.versions.contains(version) {
            return Err(MetadataError::UnsupportedVersion);
        }
        Ok(MetadataProvenance {
            owner: registration.owner.clone(),
            version,
            binding: MetadataContextBinding::from_request(request),
        })
    }

    /// Builds an immutable, request-bound snapshot containing only active authorized keys.
    ///
    /// The capture time comes from the server clock. The snapshot cannot outlive either its
    /// bounded lifetime or the canonical request deadline. Parsed, forwarded, unknown,
    /// unauthorized, wrong-context, deprecated-disallowed, removed, and exact-version-mismatched
    /// values are omitted.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when canonical authorization is denied, the request is stale, the
    /// system clock is invalid, or canonical snapshot serialization fails.
    pub fn authorize_snapshot(
        &self,
        document: &MetaDocument,
        policy: &MetadataAccessPolicy,
        request: &McpRequestContext,
        ttl: MetadataSnapshotTtl,
    ) -> Result<AuthorizedMetadataSnapshot, MetadataError> {
        let captured_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MetadataError::InvalidSystemClock)?
            .as_secs();
        self.authorize_snapshot_at(document, policy, request, ttl, captured_at_unix)
    }

    pub(crate) fn authorize_snapshot_at(
        &self,
        document: &MetaDocument,
        policy: &MetadataAccessPolicy,
        request: &McpRequestContext,
        ttl: MetadataSnapshotTtl,
        captured_at_unix: u64,
    ) -> Result<AuthorizedMetadataSnapshot, MetadataError> {
        if request.canonical().invocation().authorization() != Decision::Allow {
            return Err(MetadataError::UnauthorizedContext);
        }
        let deadline_unix =
            u64::try_from(request.canonical().invocation().deadline().unix_timestamp())
                .map_err(|_| MetadataError::StaleRequestContext)?;
        let ttl_expiry = captured_at_unix
            .checked_add(ttl.as_seconds())
            .ok_or(MetadataError::StaleRequestContext)?;
        let valid_until_unix = deadline_unix.min(ttl_expiry);
        if valid_until_unix <= captured_at_unix {
            return Err(MetadataError::StaleRequestContext);
        }

        let binding = MetadataContextBinding::from_request(request);
        let mut active = BTreeMap::new();
        for key in document.values.keys() {
            let Ok(key) = MetadataKey::parse(key.clone()) else {
                continue;
            };
            let MetadataResolution::Active(metadata) =
                document.resolve(&key, self, policy, request)
            else {
                continue;
            };
            let mut envelope = serde_json::Map::new();
            envelope.insert("value".to_owned(), metadata.value.clone());
            envelope.insert("version".to_owned(), Value::from(metadata.version));
            active.insert(key.as_str().to_owned(), Value::Object(envelope));
        }
        let authorized_set_fingerprint =
            authorized_set_fingerprint(&self.fingerprint, &binding, policy, &active)?;
        let evidence_fingerprint = evidence_fingerprint(
            &authorized_set_fingerprint,
            captured_at_unix,
            valid_until_unix,
        );
        Ok(AuthorizedMetadataSnapshot {
            active,
            binding,
            authorized_set_fingerprint,
            evidence_fingerprint,
            captured_at_unix,
            valid_until_unix,
        })
    }
}

/// Per-request exact-version and lifecycle access policy for registered metadata keys.
#[derive(Clone, Debug, Default)]
pub struct MetadataAccessPolicy {
    allow_preview: bool,
    allow_deprecated: bool,
    accepted_versions: BTreeMap<MetadataKey, u16>,
}

impl MetadataAccessPolicy {
    /// Creates a policy that authorizes no metadata keys.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Creates a bounded trusted access policy with one exact accepted version per key.
    ///
    /// This policy is a server authorization result, not client metadata. A key absent from the
    /// map is not public even when it is registered and has trusted owner provenance.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for malformed, duplicate, zero-version, or excessive entries.
    pub fn try_new(
        allow_preview: bool,
        allow_deprecated: bool,
        accepted_versions: impl IntoIterator<Item = (String, u16)>,
    ) -> Result<Self, MetadataError> {
        let mut versions = BTreeMap::new();
        for (key, version) in accepted_versions {
            if versions.len() >= MAX_REGISTERED_KEYS || version == 0 {
                return Err(MetadataError::InvalidAccessPolicy);
            }
            let key = MetadataKey::parse(key)?;
            if versions.insert(key, version).is_some() {
                return Err(MetadataError::KeyCollision);
            }
        }
        Ok(Self {
            allow_preview,
            allow_deprecated,
            accepted_versions: versions,
        })
    }
}

/// A versioned registered metadata value.
#[derive(Clone, PartialEq)]
pub struct VersionedMetadataValue {
    version: u16,
    value: Value,
}

impl VersionedMetadataValue {
    /// Creates a non-zero versioned value. Bounds are enforced on document insertion.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::UnsupportedVersion`] for version zero.
    pub fn try_new(version: u16, value: Value) -> Result<Self, MetadataError> {
        if version == 0 {
            return Err(MetadataError::UnsupportedVersion);
        }
        Ok(Self { version, value })
    }

    fn into_json(self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("value".to_owned(), self.value);
        object.insert("version".to_owned(), Value::from(self.version));
        Value::Object(object)
    }
}

impl fmt::Debug for VersionedMetadataValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedMetadataValue")
            .field("version", &self.version)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// A registered metadata value that passed every ownership, context, lifecycle, and policy guard.
#[derive(Clone, Copy)]
pub struct RegisteredMetadata<'a> {
    /// Registered key ownership declaration.
    pub registration: &'a MetadataRegistration,
    /// Exact accepted metadata version.
    pub version: u16,
    /// Bounded metadata payload.
    pub value: &'a Value,
}

impl fmt::Debug for RegisteredMetadata<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredMetadata")
            .field("registration", &"[redacted]")
            .field("version", &self.version)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Safe resolution state for one retained metadata key.
#[derive(Clone, Copy, Debug)]
pub enum MetadataResolution<'a> {
    /// A registered value may enter the request's authorized snapshot.
    Active(RegisteredMetadata<'a>),
    /// A registered key was retained but cannot activate or be published.
    Inert(MetadataInertReason),
    /// An unregistered key is retained solely for internal semantic round trips.
    Unknown,
}

/// Redacted reason a retained registered key has no public meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataInertReason {
    /// The trusted access policy did not accept this key.
    NotNegotiated,
    /// The retained value does not use the exact versioned envelope.
    MalformedEnvelope,
    /// Parsed or forwarded metadata lacks trusted registered-owner provenance.
    UntrustedSource,
    /// The exact value version differs from registration or access policy.
    UnsupportedVersion,
    /// Canonical authorization denied the request.
    Unauthorized,
    /// Owner provenance was established for another canonical request, principal, or tenant.
    ContextMismatch,
    /// Preview metadata was not explicitly permitted by trusted access policy.
    PreviewNotAllowed,
    /// Deprecated metadata was not explicitly permitted by trusted access policy.
    DeprecatedNotAllowed,
    /// Removed metadata is internal-retention-only.
    Removed,
}

impl MetadataInertReason {
    /// Returns a stable, value-free telemetry code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotNegotiated => "meta_not_negotiated",
            Self::MalformedEnvelope => "meta_malformed_envelope",
            Self::UntrustedSource => "meta_untrusted_source",
            Self::UnsupportedVersion => "meta_unsupported_version",
            Self::Unauthorized => "meta_unauthorized",
            Self::ContextMismatch => "meta_context_mismatch",
            Self::PreviewNotAllowed => "meta_preview_not_allowed",
            Self::DeprecatedNotAllowed => "meta_deprecated_not_allowed",
            Self::Removed => "meta_removed",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct MetadataContextBinding {
    request_id: String,
    subject_id: String,
    tenant_id: Option<String>,
    tenant_mode: TenantMode,
    data_policy: String,
    scopes: Vec<String>,
}

impl MetadataContextBinding {
    fn from_request(request: &McpRequestContext) -> Self {
        let invocation = request.canonical().invocation();
        Self {
            request_id: invocation.request_id().to_string(),
            subject_id: invocation.principal().subject_id.to_string(),
            tenant_id: invocation
                .tenant_id()
                .map(|tenant_id| tenant_id.to_string()),
            tenant_mode: request.canonical().tenant_mode(),
            data_policy: invocation.data_policy().as_str().to_owned(),
            scopes: invocation
                .principal()
                .scopes
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
        }
    }

    fn update_digest(&self, digest: &mut Sha256) {
        update_text(digest, &self.request_id);
        update_text(digest, &self.subject_id);
        update_optional_text(digest, self.tenant_id.as_deref());
        digest.update([match self.tenant_mode {
            TenantMode::Global => 1,
            TenantMode::Tenant => 2,
            TenantMode::Principal => 3,
        }]);
        update_text(digest, &self.data_policy);
        digest.update(
            u64::try_from(self.scopes.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for scope in &self.scopes {
            update_text(digest, scope);
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct MetadataProvenance {
    owner: MetadataOwner,
    version: u16,
    binding: MetadataContextBinding,
}

/// A bounded `_meta` object whose unknown values are retained only on internal seams.
///
/// This type intentionally does not implement `Serialize`. Parsed values have no owner
/// provenance, and provenance never enters JSON. Only [`AuthorizedMetadataSnapshot`] may reach the
/// public report adapter.
#[derive(Clone, PartialEq)]
pub struct MetaDocument {
    values: BTreeMap<String, Value>,
    owned_keys: BTreeMap<MetadataKey, MetadataProvenance>,
    limits: MetadataLimits,
}

impl fmt::Debug for MetaDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetaDocument")
            .field("values", &"[redacted]")
            .field("owned_keys", &"[redacted]")
            .field("limits", &self.limits)
            .finish()
    }
}

impl MetaDocument {
    /// Creates an empty bounded metadata object.
    #[must_use]
    pub fn empty(limits: MetadataLimits) -> Self {
        Self {
            values: BTreeMap::new(),
            owned_keys: BTreeMap::new(),
            limits,
        }
    }

    /// Parses an encoded `_meta` object with duplicate-key detection before semantic retention.
    ///
    /// Parsed registered-looking values remain inert because JSON cannot establish ownership.
    /// Unknown values are retained semantically rather than byte-for-byte; insignificant JSON
    /// whitespace and object insertion order are not preserved.
    ///
    /// # Errors
    ///
    /// Returns a redacted parsing or budget error.
    pub fn parse_json(input: &[u8], limits: MetadataLimits) -> Result<Self, MetadataError> {
        validate_encoded(input, limits)?;
        let value =
            serde_json::from_slice::<Value>(input).map_err(|_| MetadataError::InvalidJson)?;
        let Value::Object(object) = value else {
            return Err(MetadataError::RootNotObject);
        };
        Ok(Self {
            values: object.into_iter().collect(),
            owned_keys: BTreeMap::new(),
            limits,
        })
    }

    /// Resolves a key only for its trusted owner, exact version, canonical context, and policy.
    #[must_use]
    pub fn resolve<'a>(
        &'a self,
        key: &MetadataKey,
        registry: &'a MetadataKeyRegistry,
        policy: &MetadataAccessPolicy,
        request: &McpRequestContext,
    ) -> MetadataResolution<'a> {
        let Some(raw) = self.values.get(key.as_str()) else {
            return MetadataResolution::Unknown;
        };
        let Some(registration) = registry.registration(key) else {
            return MetadataResolution::Unknown;
        };
        let Some((version, value)) = parse_versioned(raw) else {
            return MetadataResolution::Inert(MetadataInertReason::MalformedEnvelope);
        };
        let Some(provenance) = self.owned_keys.get(key) else {
            return MetadataResolution::Inert(MetadataInertReason::UntrustedSource);
        };
        if provenance.owner != registration.owner || provenance.version != version {
            return MetadataResolution::Inert(MetadataInertReason::UntrustedSource);
        }
        if request.canonical().invocation().authorization() != Decision::Allow {
            return MetadataResolution::Inert(MetadataInertReason::Unauthorized);
        }
        if provenance.binding != MetadataContextBinding::from_request(request) {
            return MetadataResolution::Inert(MetadataInertReason::ContextMismatch);
        }
        let Some(accepted) = policy.accepted_versions.get(key) else {
            return MetadataResolution::Inert(MetadataInertReason::NotNegotiated);
        };
        if !registration.versions.contains(version) || version != *accepted {
            return MetadataResolution::Inert(MetadataInertReason::UnsupportedVersion);
        }
        match registration.lifecycle {
            MetadataLifecycle::Preview if !policy.allow_preview => {
                MetadataResolution::Inert(MetadataInertReason::PreviewNotAllowed)
            }
            MetadataLifecycle::Deprecated if !policy.allow_deprecated => {
                MetadataResolution::Inert(MetadataInertReason::DeprecatedNotAllowed)
            }
            MetadataLifecycle::Removed => MetadataResolution::Inert(MetadataInertReason::Removed),
            MetadataLifecycle::Preview
            | MetadataLifecycle::Stable
            | MetadataLifecycle::Deprecated => MetadataResolution::Active(RegisteredMetadata {
                registration,
                version,
                value,
            }),
        }
    }

    /// Returns whether a key is retained, without granting interpretation or publication rights.
    #[must_use]
    pub fn contains_retained(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
    #[cfg(test)]
    fn forwarding_json(&self) -> Result<Vec<u8>, MetadataError> {
        serde_json::to_vec(&self.values).map_err(|_| MetadataError::Serialization)
    }

    fn insert_bounded(&mut self, key: &str, value: Value) -> Result<(), MetadataError> {
        if self.values.contains_key(key) {
            return Err(MetadataError::KeyCollision);
        }
        let mut candidate = self.values.clone();
        candidate.insert(key.to_owned(), value);
        let encoded = serde_json::to_vec(&candidate).map_err(|_| MetadataError::Serialization)?;
        validate_encoded(&encoded, self.limits)?;
        self.values = candidate;
        Ok(())
    }

    fn replace_bounded(&mut self, key: &str, value: Value) -> Result<(), MetadataError> {
        let mut candidate = self.values.clone();
        if candidate.insert(key.to_owned(), value).is_none() {
            return Err(MetadataError::MissingRetainedKey);
        }
        let encoded = serde_json::to_vec(&candidate).map_err(|_| MetadataError::Serialization)?;
        validate_encoded(&encoded, self.limits)?;
        self.values = candidate;
        Ok(())
    }
}

/// Immutable public-projection input minted only by [`MetadataKeyRegistry`].
///
/// Values are already owner-verified, exactly versioned, access-policy-filtered, and bound to one
/// canonical request/principal/tenant context. No method exposes the retained raw document.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedMetadataSnapshot {
    active: BTreeMap<String, Value>,
    binding: MetadataContextBinding,
    authorized_set_fingerprint: [u8; 32],
    evidence_fingerprint: [u8; 32],
    captured_at_unix: u64,
    valid_until_unix: u64,
}

impl fmt::Debug for AuthorizedMetadataSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedMetadataSnapshot")
            .field("active", &"[redacted]")
            .field("binding", &"[redacted]")
            .field("authorized_set_fingerprint", &"[redacted]")
            .field("evidence_fingerprint", &"[redacted]")
            .field("captured_at_unix", &self.captured_at_unix)
            .field("valid_until_unix", &self.valid_until_unix)
            .finish()
    }
}

impl AuthorizedMetadataSnapshot {
    /// Returns the number of active authorized keys in the immutable snapshot.
    #[must_use]
    pub fn active_key_count(&self) -> usize {
        self.active.len()
    }

    /// Returns the server capture time as a Unix second.
    #[must_use]
    pub const fn captured_at_unix(&self) -> u64 {
        self.captured_at_unix
    }

    /// Returns the exclusive freshness deadline as a Unix second.
    #[must_use]
    pub const fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }

    /// Returns the immutable SHA-256 identity of the canonical authorized set.
    #[must_use]
    pub const fn authorized_set_fingerprint(&self) -> [u8; 32] {
        self.authorized_set_fingerprint
    }

    pub(crate) fn active(&self) -> &BTreeMap<String, Value> {
        &self.active
    }

    pub(crate) fn evidence_fingerprint(&self) -> [u8; 32] {
        self.evidence_fingerprint
    }

    pub(crate) fn validate_for(
        &self,
        request: &McpRequestContext,
        now_unix: u64,
    ) -> Result<(), SnapshotValidationError> {
        if now_unix < self.captured_at_unix || now_unix >= self.valid_until_unix {
            return Err(SnapshotValidationError);
        }
        if request.canonical().invocation().authorization() != Decision::Allow
            || self.binding != MetadataContextBinding::from_request(request)
        {
            return Err(SnapshotValidationError);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotValidationError;

/// Value-free telemetry dimensions for one retained metadata document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataTelemetryReport {
    /// Registered values that passed every request guard.
    pub active_keys: u16,
    /// Registered values retained without public meaning.
    pub inert_keys: u16,
    /// Unregistered values retained only for internal compatibility forwarding.
    pub unknown_keys: u16,
}

impl MetadataTelemetryReport {
    /// Produces counts only; key names, owners, versions, identities, and values are never reported.
    #[must_use]
    pub fn from_document(
        document: &MetaDocument,
        registry: &MetadataKeyRegistry,
        policy: &MetadataAccessPolicy,
        request: &McpRequestContext,
    ) -> Self {
        let mut report = Self {
            active_keys: 0,
            inert_keys: 0,
            unknown_keys: 0,
        };
        for key in document.values.keys() {
            let parsed_key = MetadataKey::parse(key.clone()).ok();
            let resolution = parsed_key
                .as_ref()
                .map_or(MetadataResolution::Unknown, |key| {
                    document.resolve(key, registry, policy, request)
                });
            match resolution {
                MetadataResolution::Active(_) => report.active_keys += 1,
                MetadataResolution::Inert(_) => report.inert_keys += 1,
                MetadataResolution::Unknown => report.unknown_keys += 1,
            }
        }
        report
    }
}

/// Bounded metadata parsing, ownership, authorization, or snapshot failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MetadataError {
    /// A caller attempted to configure limits outside hard ceilings.
    #[error("invalid metadata limits")]
    InvalidLimits,
    /// The encoded object exceeds the configured byte ceiling.
    #[error("metadata byte ceiling exceeded")]
    InputTooLarge,
    /// A JSON value exceeds the configured depth ceiling.
    #[error("metadata depth ceiling exceeded")]
    DepthExceeded,
    /// The total object-key count exceeds the configured ceiling.
    #[error("metadata key ceiling exceeded")]
    KeyLimitExceeded,
    /// A metadata key or string value exceeds the configured ceiling.
    #[error("metadata string ceiling exceeded")]
    StringTooLong,
    /// The encoded bytes are not one valid JSON value.
    #[error("invalid metadata JSON")]
    InvalidJson,
    /// The metadata root is not an object.
    #[error("metadata root must be an object")]
    RootNotObject,
    /// An object repeats a key.
    #[error("duplicate metadata key")]
    DuplicateKey,
    /// A registered key is malformed.
    #[error("invalid metadata key")]
    InvalidKey,
    /// An ownership identifier is malformed.
    #[error("invalid metadata owner")]
    InvalidOwner,
    /// A server support declaration is invalid.
    #[error("invalid metadata version range")]
    InvalidVersionRange,
    /// The ownership registry exceeds its hard key ceiling.
    #[error("too many metadata registrations")]
    TooManyRegistrations,
    /// Two owners attempted to register the same metadata key.
    #[error("metadata key ownership collision")]
    KeyOwnershipCollision,
    /// An insertion or policy would repeat a retained key.
    #[error("metadata key collision")]
    KeyCollision,
    /// Trusted re-establishment targeted a key that is not retained.
    #[error("retained metadata key is missing")]
    MissingRetainedKey,
    /// The key has no registered owner.
    #[error("unregistered metadata key")]
    UnregisteredKey,
    /// A module attempted to emit another owner's key.
    #[error("wrong metadata key owner")]
    WrongOwner,
    /// A value does not use an exact server-supported metadata version.
    #[error("unsupported metadata version")]
    UnsupportedVersion,
    /// Per-request exact-version access policy is invalid or excessive.
    #[error("invalid metadata access policy")]
    InvalidAccessPolicy,
    /// The canonical request context did not authorize metadata projection.
    #[error("metadata request context is unauthorized")]
    UnauthorizedContext,
    /// The canonical request context is expired or cannot bound snapshot freshness.
    #[error("metadata request context is stale")]
    StaleRequestContext,
    /// The configured snapshot lifetime is invalid.
    #[error("invalid metadata snapshot lifetime")]
    InvalidSnapshotTtl,
    /// The server clock cannot produce trustworthy freshness evidence.
    #[error("metadata system clock is invalid")]
    InvalidSystemClock,
    /// A bounded metadata object or fingerprint input could not be serialized.
    #[error("metadata serialization failed")]
    Serialization,
}

fn parse_versioned(value: &Value) -> Option<(u16, &Value)> {
    let object = value.as_object()?;
    if object.len() != 2 {
        return None;
    }
    let version = u16::try_from(object.get("version")?.as_u64()?).ok()?;
    if version == 0 {
        return None;
    }
    Some((version, object.get("value")?))
}

fn registry_fingerprint(registrations: &BTreeMap<MetadataKey, MetadataRegistration>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REGISTRY_DOMAIN);
    for registration in registrations.values() {
        update_text(&mut digest, registration.key.as_str());
        update_text(&mut digest, registration.owner.as_str());
        digest.update(registration.versions.minimum.to_be_bytes());
        digest.update(registration.versions.maximum.to_be_bytes());
        digest.update([registration.lifecycle.fingerprint_code()]);
    }
    digest.finalize().into()
}

fn authorized_set_fingerprint(
    registry_fingerprint: &[u8; 32],
    binding: &MetadataContextBinding,
    policy: &MetadataAccessPolicy,
    active: &BTreeMap<String, Value>,
) -> Result<[u8; 32], MetadataError> {
    let mut digest = Sha256::new();
    digest.update(FINGERPRINT_DOMAIN);
    digest.update(registry_fingerprint);
    binding.update_digest(&mut digest);
    digest.update([
        u8::from(policy.allow_preview),
        u8::from(policy.allow_deprecated),
    ]);
    for (key, version) in &policy.accepted_versions {
        update_text(&mut digest, key.as_str());
        digest.update(version.to_be_bytes());
    }
    let canonical = serde_json::to_vec(active).map_err(|_| MetadataError::Serialization)?;
    update_bytes(&mut digest, &canonical);
    Ok(digest.finalize().into())
}

fn evidence_fingerprint(
    authorized_set_fingerprint: &[u8; 32],
    captured_at_unix: u64,
    valid_until_unix: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(EVIDENCE_DOMAIN);
    digest.update(authorized_set_fingerprint);
    digest.update(captured_at_unix.to_be_bytes());
    digest.update(valid_until_unix.to_be_bytes());
    digest.finalize().into()
}

fn update_optional_text(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            update_text(digest, value);
        }
        None => digest.update([0]),
    }
}

fn update_text(digest: &mut Sha256, value: &str) {
    update_bytes(digest, value.as_bytes());
}

fn update_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

pub(crate) fn encoded_fingerprint(fingerprint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in fingerprint {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn validate_encoded(input: &[u8], limits: MetadataLimits) -> Result<(), MetadataError> {
    if input.len() > limits.max_bytes {
        return Err(MetadataError::InputTooLarge);
    }
    let mut state = ValidationState {
        limits,
        key_count: 0,
        violation: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let parsed = BudgetSeed {
        state: &mut state,
        depth: 1,
    }
    .deserialize(&mut deserializer);
    if parsed.is_err() || deserializer.end().is_err() {
        return Err(state.violation.unwrap_or(MetadataError::InvalidJson));
    }
    Ok(())
}

struct ValidationState {
    limits: MetadataLimits,
    key_count: usize,
    violation: Option<MetadataError>,
}

impl ValidationState {
    fn reject<E: de::Error>(&mut self, error: MetadataError) -> Result<(), E> {
        self.violation = Some(error);
        Err(E::custom("bounded metadata rejected"))
    }

    fn check_string<E: de::Error>(&mut self, value: &str) -> Result<(), E> {
        if value.len() > self.limits.max_string_bytes {
            return self.reject(MetadataError::StringTooLong);
        }
        Ok(())
    }
}

struct BudgetSeed<'a> {
    state: &'a mut ValidationState,
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for BudgetSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > self.state.limits.max_depth {
            return self.state.reject(MetadataError::DepthExceeded);
        }
        deserializer.deserialize_any(BudgetVisitor {
            state: self.state,
            depth: self.depth,
        })
    }
}

struct BudgetVisitor<'a> {
    state: &'a mut ValidationState,
    depth: usize,
}

impl<'de> Visitor<'de> for BudgetVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.check_string(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.check_string(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.check_string(&value)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(BudgetSeed {
                state: &mut *self.state,
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut local_keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.state.check_string(&key)?;
            if !local_keys.insert(key) {
                return self.state.reject(MetadataError::DuplicateKey);
            }
            self.state.key_count += 1;
            if self.state.key_count > self.state.limits.max_keys {
                return self.state.reject(MetadataError::KeyLimitExceeded);
            }
            map.next_value_seed(BudgetSeed {
                state: &mut *self.state,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use omnius_auth_core::{SubjectId, TenantId};
    use omnius_authz_basic::{Decision, DenyReason};

    use super::*;
    use crate::test_support::{RequestContextOptions, request_context};

    fn key(value: &str) -> Result<MetadataKey, MetadataError> {
        MetadataKey::parse(value)
    }

    fn owner(value: &str) -> Result<MetadataOwner, MetadataError> {
        MetadataOwner::parse(value)
    }

    fn registry(lifecycle: MetadataLifecycle) -> Result<MetadataKeyRegistry, MetadataError> {
        MetadataKeyRegistry::try_new([MetadataRegistration::new(
            key("com.example/known")?,
            owner("example-module")?,
            MetadataVersionRange::try_new(1, 2)?,
            lifecycle,
        )])
    }

    fn accepted(version: u16) -> Result<MetadataAccessPolicy, MetadataError> {
        MetadataAccessPolicy::try_new(true, false, [("com.example/known".to_owned(), version)])
    }

    #[test]
    fn unknown_metadata_is_retained_internally_but_parsed_keys_cannot_activate()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = request_context(&RequestContextOptions::default())?;
        let mut document = MetaDocument::parse_json(
            br#"{"future.example/value":{"nested":[1,true,null]}}"#,
            MetadataLimits::default(),
        )?;
        let registry = registry(MetadataLifecycle::Preview)?;
        registry.insert_owned(
            &mut document,
            &owner("example-module")?,
            &key("com.example/known")?,
            VersionedMetadataValue::try_new(1, serde_json::json!({"mode": "compact"}))?,
            &context,
        )?;
        assert!(matches!(
            document.resolve(
                &key("com.example/known")?,
                &registry,
                &accepted(1)?,
                &context
            ),
            MetadataResolution::Active(RegisteredMetadata { version: 1, .. })
        ));
        assert!(matches!(
            document.resolve(
                &key("future.example/value")?,
                &registry,
                &accepted(1)?,
                &context
            ),
            MetadataResolution::Unknown
        ));

        let forwarded = document.forwarding_json()?;
        let mut reparsed = MetaDocument::parse_json(&forwarded, MetadataLimits::default())?;
        assert_eq!(reparsed.forwarding_json()?, forwarded);
        assert!(reparsed.contains_retained("future.example/value"));
        assert!(matches!(
            reparsed.resolve(
                &key("com.example/known")?,
                &registry,
                &accepted(1)?,
                &context
            ),
            MetadataResolution::Inert(MetadataInertReason::UntrustedSource)
        ));
        registry.reestablish_owned(
            &mut reparsed,
            &owner("example-module")?,
            &key("com.example/known")?,
            VersionedMetadataValue::try_new(1, serde_json::json!({"mode": "trusted"}))?,
            &context,
        )?;
        assert!(matches!(
            reparsed.resolve(
                &key("com.example/known")?,
                &registry,
                &accepted(1)?,
                &context
            ),
            MetadataResolution::Active(RegisteredMetadata { version: 1, .. })
        ));
        assert!(reparsed.contains_retained("future.example/value"));
        Ok(())
    }

    #[test]
    fn exact_version_mismatch_is_inert_even_inside_server_support_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = request_context(&RequestContextOptions::default())?;
        let registry = registry(MetadataLifecycle::Stable)?;
        let mut document = MetaDocument::empty(MetadataLimits::default());
        registry.insert_owned(
            &mut document,
            &owner("example-module")?,
            &key("com.example/known")?,
            VersionedMetadataValue::try_new(1, Value::Bool(true))?,
            &context,
        )?;
        assert!(matches!(
            document.resolve(
                &key("com.example/known")?,
                &registry,
                &accepted(2)?,
                &context
            ),
            MetadataResolution::Inert(MetadataInertReason::UnsupportedVersion)
        ));
        Ok(())
    }

    #[test]
    fn snapshots_filter_cross_tenant_denied_and_policy_unauthorized_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let subject = SubjectId::new();
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let context_a = request_context(&RequestContextOptions {
            subject_id: Some(subject),
            tenant_id: Some(tenant_a),
            ..RequestContextOptions::default()
        })?;
        let context_b = request_context(&RequestContextOptions {
            subject_id: Some(subject),
            tenant_id: Some(tenant_b),
            ..RequestContextOptions::default()
        })?;
        let registry = registry(MetadataLifecycle::Stable)?;
        let mut document = MetaDocument::empty(MetadataLimits::default());
        registry.insert_owned(
            &mut document,
            &owner("example-module")?,
            &key("com.example/known")?,
            VersionedMetadataValue::try_new(1, Value::String("tenant-a-secret".to_owned()))?,
            &context_a,
        )?;
        let ttl = MetadataSnapshotTtl::from_seconds(30)?;
        let cross_tenant =
            registry.authorize_snapshot(&document, &accepted(1)?, &context_b, ttl)?;
        assert_eq!(cross_tenant.active_key_count(), 0);
        let denied_by_policy = registry.authorize_snapshot(
            &document,
            &MetadataAccessPolicy::deny_all(),
            &context_a,
            ttl,
        )?;
        assert_eq!(denied_by_policy.active_key_count(), 0);

        let denied = request_context(&RequestContextOptions {
            subject_id: Some(subject),
            tenant_id: Some(tenant_a),
            decision: Decision::Deny(DenyReason::NotEntitled),
            ..RequestContextOptions::default()
        })?;
        assert!(matches!(
            registry.authorize_snapshot(&document, &accepted(1)?, &denied, ttl),
            Err(MetadataError::UnauthorizedContext)
        ));
        Ok(())
    }

    #[test]
    fn deprecated_and_removed_keys_never_bypass_lifecycle_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = request_context(&RequestContextOptions::default())?;
        let mut document = MetaDocument::empty(MetadataLimits::default());
        let deprecated = registry(MetadataLifecycle::Deprecated)?;
        deprecated.insert_owned(
            &mut document,
            &owner("example-module")?,
            &key("com.example/known")?,
            VersionedMetadataValue::try_new(1, Value::Bool(true))?,
            &context,
        )?;
        let denied = deprecated.authorize_snapshot(
            &document,
            &accepted(1)?,
            &context,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        assert_eq!(denied.active_key_count(), 0);
        let allowed_policy =
            MetadataAccessPolicy::try_new(true, true, [("com.example/known".to_owned(), 1)])?;
        let allowed = deprecated.authorize_snapshot(
            &document,
            &allowed_policy,
            &context,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        assert_eq!(allowed.active_key_count(), 1);

        let removed = registry(MetadataLifecycle::Removed)?;
        let removed_snapshot = removed.authorize_snapshot(
            &document,
            &allowed_policy,
            &context,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        assert_eq!(removed_snapshot.active_key_count(), 0);
        Ok(())
    }

    #[test]
    fn parsing_rejects_duplicate_keys_depth_size_key_and_string_overruns()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = MetadataLimits::try_new(64, 3, 2, 8)?;
        assert_eq!(
            MetaDocument::parse_json(br#"{"a":1,"a":2}"#, limits),
            Err(MetadataError::DuplicateKey)
        );
        assert_eq!(
            MetaDocument::parse_json(br#"{"a":[[1]]}"#, limits),
            Err(MetadataError::DepthExceeded)
        );
        assert_eq!(
            MetaDocument::parse_json(br#"{"a":1,"b":2,"c":3}"#, limits),
            Err(MetadataError::KeyLimitExceeded)
        );
        assert_eq!(
            MetaDocument::parse_json(br#"{"a":"123456789"}"#, limits),
            Err(MetadataError::StringTooLong)
        );
        assert_eq!(
            MetaDocument::parse_json(&[b' '; 65], limits),
            Err(MetadataError::InputTooLarge)
        );
        Ok(())
    }

    #[test]
    fn ownership_and_retained_key_collisions_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let context = request_context(&RequestContextOptions::default())?;
        let registration = MetadataRegistration::new(
            key("com.example/known")?,
            owner("owner-a")?,
            MetadataVersionRange::try_new(1, 1)?,
            MetadataLifecycle::Stable,
        );
        assert_eq!(
            MetadataKeyRegistry::try_new([registration.clone(), registration.clone()]).err(),
            Some(MetadataError::KeyOwnershipCollision)
        );
        let registry = MetadataKeyRegistry::try_new([registration])?;
        let mut document = MetaDocument::parse_json(
            br#"{"com.example/known":{"version":1,"value":{}}}"#,
            MetadataLimits::default(),
        )?;
        let value = VersionedMetadataValue::try_new(1, Value::Null)?;
        assert_eq!(
            registry.insert_owned(
                &mut document,
                &owner("owner-b")?,
                &key("com.example/known")?,
                value.clone(),
                &context,
            ),
            Err(MetadataError::WrongOwner)
        );
        assert_eq!(
            registry.insert_owned(
                &mut document,
                &owner("owner-a")?,
                &key("com.example/known")?,
                value,
                &context,
            ),
            Err(MetadataError::KeyCollision)
        );
        Ok(())
    }

    #[test]
    fn telemetry_contains_counts_but_no_metadata_values() -> Result<(), Box<dyn std::error::Error>>
    {
        let context = request_context(&RequestContextOptions::default())?;
        let document = MetaDocument::parse_json(
            br#"{"com.example/known":{"version":1,"value":"secret"},"unknown.example/key":"also-secret"}"#,
            MetadataLimits::default(),
        )?;
        let report = MetadataTelemetryReport::from_document(
            &document,
            &registry(MetadataLifecycle::Preview)?,
            &MetadataAccessPolicy::deny_all(),
            &context,
        );
        assert_eq!(
            report,
            MetadataTelemetryReport {
                active_keys: 0,
                inert_keys: 1,
                unknown_keys: 1,
            }
        );
        Ok(())
    }
}
