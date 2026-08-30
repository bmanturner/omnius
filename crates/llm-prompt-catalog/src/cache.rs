use std::{collections::BTreeSet, fmt};

use async_trait::async_trait;
use omnius_llm_core::{ModelCapability, ModelCapabilityDeclaration, ModelCapabilityKey};
use thiserror::Error;

use crate::{
    ContentDigest, DataClassification, ModelRevisionId, PolicyRevisionId, PrincipalId,
    PromptRevisionNumber, RouteId, SchemaRevisionId, TenantId, ToolRevisionId,
};

const CACHE_KEY_PREFIX: &str = "llm:v1:";
const MAX_CACHE_VALUE_BYTES: usize = 4_194_304;
const MAX_REVISION_SET_ITEMS: usize = 256;
const MAX_PROVIDER_CACHE_TTL_SECONDS: u64 = 86_400;

/// Security scope that prevents cross-tenant, cross-principal, or stale-policy cache reuse.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheSecurityScope {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    policy_revision: PolicyRevisionId,
    grant_revision: PolicyRevisionId,
    route_id: RouteId,
    classification: DataClassification,
    sensitive: bool,
}

impl CacheSecurityScope {
    /// Creates a complete security and route isolation scope.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        policy_revision: PolicyRevisionId,
        grant_revision: PolicyRevisionId,
        route_id: RouteId,
        classification: DataClassification,
        sensitive: bool,
    ) -> Self {
        Self {
            tenant_id,
            principal_id,
            policy_revision,
            grant_revision,
            route_id,
            classification,
            sensitive,
        }
    }

    /// Borrows the tenant isolation identifier.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Borrows the principal isolation identifier.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Borrows the exact policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevisionId {
        &self.policy_revision
    }

    /// Borrows the exact authorization grant revision.
    #[must_use]
    pub const fn grant_revision(&self) -> &PolicyRevisionId {
        &self.grant_revision
    }

    /// Borrows the logical route identifier.
    #[must_use]
    pub const fn route_id(&self) -> &RouteId {
        &self.route_id
    }

    /// Returns the data classification represented by the key.
    #[must_use]
    pub const fn classification(&self) -> DataClassification {
        self.classification
    }

    /// Returns whether the key may contain explicitly admitted sensitive content.
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        self.sensitive
    }
}

impl fmt::Debug for CacheSecurityScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheSecurityScope")
            .field("tenant_id", &"[REDACTED]")
            .field("principal_id", &"[REDACTED]")
            .field("policy_revision", &"[REDACTED]")
            .field("grant_revision", &"[REDACTED]")
            .field("route_id", &"[REDACTED]")
            .field("classification", &self.classification)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

/// Exact model and generation semantics represented by an application cache key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheModelSemantics {
    model_revision: ModelRevisionId,
    generation_options_digest: ContentDigest,
    output_contract_digest: ContentDigest,
}

impl CacheModelSemantics {
    /// Creates exact model, generation-option, and output-contract semantics.
    #[must_use]
    pub const fn new(
        model_revision: ModelRevisionId,
        generation_options_digest: ContentDigest,
        output_contract_digest: ContentDigest,
    ) -> Self {
        Self {
            model_revision,
            generation_options_digest,
            output_contract_digest,
        }
    }
}

/// Exact prompt semantics represented by an application cache key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePromptSemantics {
    prompt_revision: PromptRevisionNumber,
    prompt_content_digest: ContentDigest,
    variables_digest: ContentDigest,
    rendered_prompt_digest: ContentDigest,
}

impl CachePromptSemantics {
    /// Creates exact prompt revision, source, variables, and rendered-content semantics.
    #[must_use]
    pub const fn new(
        prompt_revision: PromptRevisionNumber,
        prompt_content_digest: ContentDigest,
        variables_digest: ContentDigest,
        rendered_prompt_digest: ContentDigest,
    ) -> Self {
        Self {
            prompt_revision,
            prompt_content_digest,
            variables_digest,
            rendered_prompt_digest,
        }
    }
}

/// Ordered revision dependencies and context-selection semantics for a cache key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheDependencies {
    tool_revisions: BTreeSet<ToolRevisionId>,
    schema_revisions: BTreeSet<SchemaRevisionId>,
    context_manifest_digest: ContentDigest,
}

impl CacheDependencies {
    /// Creates bounded, canonically ordered dependency revision sets.
    ///
    /// # Errors
    ///
    /// Returns [`CacheKeyError::TooManyRevisions`] when either set exceeds 256 entries.
    pub fn new(
        tool_revisions: BTreeSet<ToolRevisionId>,
        schema_revisions: BTreeSet<SchemaRevisionId>,
        context_manifest_digest: ContentDigest,
    ) -> Result<Self, CacheKeyError> {
        if tool_revisions.len() > MAX_REVISION_SET_ITEMS
            || schema_revisions.len() > MAX_REVISION_SET_ITEMS
        {
            return Err(CacheKeyError::TooManyRevisions);
        }
        Ok(Self {
            tool_revisions,
            schema_revisions,
            context_manifest_digest,
        })
    }
}

/// Whether an application cache entry represents prompt material or normalized model output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CacheContentKind {
    /// Policy-approved normalized rendered prompt material.
    Prompt = 0,
    /// Policy-approved normalized model response material.
    Response = 1,
}

/// Complete semantic descriptor used to derive one application cache key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationCacheDescriptor {
    model: CacheModelSemantics,
    prompt: CachePromptSemantics,
    dependencies: CacheDependencies,
    content_kind: CacheContentKind,
}

impl ApplicationCacheDescriptor {
    /// Creates a descriptor from all non-security, non-fence semantics.
    #[must_use]
    pub const fn new(
        model: CacheModelSemantics,
        prompt: CachePromptSemantics,
        dependencies: CacheDependencies,
        content_kind: CacheContentKind,
    ) -> Self {
        Self {
            model,
            prompt,
            dependencies,
            content_kind,
        }
    }
}

/// Monotonic revision and deletion generations used to reject stale in-flight writes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CacheFence {
    revision: u64,
    deletion_epoch: u64,
}

impl CacheFence {
    /// Creates an explicit cache fence. Zero is the initial generation.
    #[must_use]
    pub const fn new(revision: u64, deletion_epoch: u64) -> Self {
        Self {
            revision,
            deletion_epoch,
        }
    }

    /// Returns the semantic revision generation.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the deletion generation.
    #[must_use]
    pub const fn deletion_epoch(self) -> u64 {
        self.deletion_epoch
    }

    /// Advances the semantic revision without changing the deletion epoch.
    #[must_use]
    pub fn next_revision(self) -> Option<Self> {
        self.revision.checked_add(1).map(|revision| Self {
            revision,
            deletion_epoch: self.deletion_epoch,
        })
    }

    /// Advances the deletion generation and semantic revision together.
    #[must_use]
    pub fn next_deletion(self) -> Option<Self> {
        Some(Self {
            revision: self.revision.checked_add(1)?,
            deletion_epoch: self.deletion_epoch.checked_add(1)?,
        })
    }

    /// Returns whether `self` strictly advances both monotonic dimensions without regressing either.
    #[must_use]
    pub const fn strictly_advances(self, previous: Self) -> bool {
        self.revision >= previous.revision
            && self.deletion_epoch >= previous.deletion_epoch
            && (self.revision > previous.revision || self.deletion_epoch > previous.deletion_epoch)
    }
}

/// A fixed-size opaque application cache key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApplicationCacheKey(String);

impl ApplicationCacheKey {
    /// Derives a bounded key from every security and semantics input plus the active fence.
    #[must_use]
    pub fn derive(
        scope: &CacheSecurityScope,
        descriptor: &ApplicationCacheDescriptor,
        fence: CacheFence,
    ) -> Self {
        let mut bytes = Vec::with_capacity(1_024);
        append_part(&mut bytes, b"omnius-llm-application-cache/v1");
        append_part(&mut bytes, scope.tenant_id.as_str().as_bytes());
        append_part(&mut bytes, scope.principal_id.as_str().as_bytes());
        append_part(&mut bytes, scope.policy_revision.as_str().as_bytes());
        append_part(&mut bytes, scope.grant_revision.as_str().as_bytes());
        append_part(&mut bytes, scope.route_id.as_str().as_bytes());
        bytes.push(scope.classification as u8);
        bytes.push(u8::from(scope.sensitive));
        append_part(
            &mut bytes,
            descriptor.model.model_revision.as_str().as_bytes(),
        );
        append_part(
            &mut bytes,
            descriptor.model.generation_options_digest.as_bytes(),
        );
        append_part(
            &mut bytes,
            descriptor.model.output_contract_digest.as_bytes(),
        );
        append_u64(&mut bytes, descriptor.prompt.prompt_revision.get());
        append_part(
            &mut bytes,
            descriptor.prompt.prompt_content_digest.as_bytes(),
        );
        append_part(&mut bytes, descriptor.prompt.variables_digest.as_bytes());
        append_part(
            &mut bytes,
            descriptor.prompt.rendered_prompt_digest.as_bytes(),
        );
        append_part(
            &mut bytes,
            descriptor.dependencies.context_manifest_digest.as_bytes(),
        );
        for revision in &descriptor.dependencies.tool_revisions {
            append_part(&mut bytes, revision.as_str().as_bytes());
        }
        bytes.push(0xff);
        for revision in &descriptor.dependencies.schema_revisions {
            append_part(&mut bytes, revision.as_str().as_bytes());
        }
        bytes.push(descriptor.content_kind as u8);
        append_u64(&mut bytes, fence.revision);
        append_u64(&mut bytes, fence.deletion_epoch);
        let digest = ContentDigest::of(&bytes).to_hex();
        Self(format!("{CACHE_KEY_PREFIX}{digest}"))
    }

    /// Borrows the fixed 71-byte cache key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApplicationCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationCacheKey([REDACTED])")
    }
}

/// A policy-approved bounded normalized cache value.
#[derive(Clone, Eq, PartialEq)]
pub struct AdmittedCacheValue {
    bytes: Vec<u8>,
    classification: DataClassification,
    sensitive: bool,
}

impl AdmittedCacheValue {
    /// Borrows normalized bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the independently assigned value classification.
    #[must_use]
    pub const fn classification(&self) -> DataClassification {
        self.classification
    }

    /// Returns whether the value was explicitly admitted as sensitive content.
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        self.sensitive
    }
}

impl fmt::Debug for AdmittedCacheValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedCacheValue")
            .field("bytes", &"[REDACTED]")
            .field("classification", &self.classification)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

/// Explicit application cache policy; provider support never overrides it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationCachePolicy {
    enabled: bool,
    maximum_classification: DataClassification,
    admit_sensitive: bool,
    max_value_bytes: usize,
}

impl ApplicationCachePolicy {
    /// Creates bounded application cache policy.
    ///
    /// # Errors
    ///
    /// Returns [`CachePolicyError::InvalidLimits`] for a zero or above-ceiling value boundary.
    pub fn new(
        enabled: bool,
        maximum_classification: DataClassification,
        admit_sensitive: bool,
        max_value_bytes: usize,
    ) -> Result<Self, CachePolicyError> {
        if max_value_bytes == 0 || max_value_bytes > MAX_CACHE_VALUE_BYTES {
            return Err(CachePolicyError::InvalidLimits);
        }
        Ok(Self {
            enabled,
            maximum_classification,
            admit_sensitive,
            max_value_bytes,
        })
    }

    /// Admits normalized bytes only under classification, sensitivity, and size policy.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`CachePolicyError`] when application caching is disabled or the value
    /// is not explicitly admitted. Provider cache capability is intentionally not an input.
    pub fn admit(
        &self,
        bytes: Vec<u8>,
        classification: DataClassification,
        sensitive: bool,
    ) -> Result<AdmittedCacheValue, CachePolicyError> {
        if !self.enabled {
            return Err(CachePolicyError::Disabled);
        }
        if classification > self.maximum_classification {
            return Err(CachePolicyError::Classification);
        }
        if sensitive && !self.admit_sensitive {
            return Err(CachePolicyError::Sensitive);
        }
        if bytes.len() > self.max_value_bytes {
            return Err(CachePolicyError::ValueLimit);
        }
        Ok(AdmittedCacheValue {
            bytes,
            classification,
            sensitive,
        })
    }
}

/// Lease binding one key to the exact fence observed before a model or render operation.
#[derive(Clone, Eq, PartialEq)]
pub struct CacheLease {
    scope: CacheSecurityScope,
    key: ApplicationCacheKey,
    fence: CacheFence,
}

impl CacheLease {
    /// Borrows the security scope.
    #[must_use]
    pub const fn scope(&self) -> &CacheSecurityScope {
        &self.scope
    }

    /// Borrows the derived application key.
    #[must_use]
    pub const fn key(&self) -> &ApplicationCacheKey {
        &self.key
    }

    /// Returns the revision/deletion fence observed for the operation.
    #[must_use]
    pub const fn fence(&self) -> CacheFence {
        self.fence
    }
}

impl fmt::Debug for CacheLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CacheLease([REDACTED])")
    }
}

/// Result of a conditional cache write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheWriteOutcome {
    /// The value was stored under the still-current fence.
    Stored,
    /// Invalidation or deletion advanced the fence, so the stale value was rejected.
    Fenced,
}

/// Atomic cache storage and invalidation port.
///
/// A per-key get/put/delete provider is not sufficient by itself: implementations need one atomic
/// consistency domain for the scope fence, conditional value writes, and scope deletion.
#[async_trait]
pub trait ApplicationCacheStore: Send + Sync {
    /// Returns the current semantic/deletion fence for one complete security scope.
    async fn current_fence(
        &self,
        scope: &CacheSecurityScope,
    ) -> Result<CacheFence, CacheStoreError>;

    /// Reads only if the supplied fence is still current. Adapters MUST return values whose
    /// classification and sensitivity exactly match `scope`.
    async fn get_if_current(
        &self,
        scope: &CacheSecurityScope,
        key: &ApplicationCacheKey,
        expected_fence: CacheFence,
    ) -> Result<Option<AdmittedCacheValue>, CacheStoreError>;

    /// Writes only if the supplied fence is still current at commit time. Adapters MUST reject a
    /// value whose classification or sensitivity does not exactly match `scope`.
    async fn put_if_current(
        &self,
        scope: &CacheSecurityScope,
        key: &ApplicationCacheKey,
        expected_fence: CacheFence,
        value: AdmittedCacheValue,
    ) -> Result<CacheWriteOutcome, CacheStoreError>;

    /// Atomically advances the fence and deletes every prior value for the exact scope.
    ///
    /// Adapters MUST compare `expected_fence`, reject non-monotonic `next_fence`, commit the new
    /// fence before accepting later writes, and make all old leases return [`CacheWriteOutcome::Fenced`].
    async fn advance_fence_and_delete(
        &self,
        scope: &CacheSecurityScope,
        expected_fence: CacheFence,
        next_fence: CacheFence,
    ) -> Result<CacheFence, CacheStoreError>;
}

/// Cache orchestration that derives keys only after reading the active fence.
#[derive(Debug)]
pub struct ApplicationCache<S> {
    store: S,
}

impl<S> ApplicationCache<S>
where
    S: ApplicationCacheStore,
{
    /// Creates cache orchestration around an atomic adapter.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Reads the current fence and derives an operation lease.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free availability failure.
    pub async fn lease(
        &self,
        scope: CacheSecurityScope,
        descriptor: &ApplicationCacheDescriptor,
    ) -> Result<CacheLease, CacheStoreError> {
        let fence = self.store.current_fence(&scope).await?;
        let key = ApplicationCacheKey::derive(&scope, descriptor, fence);
        Ok(CacheLease { scope, key, fence })
    }

    /// Reads only if no revision or deletion invalidation raced the lease.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free availability failure or [`CacheStoreError::ScopeMismatch`]
    /// if an adapter returns a value under the wrong classification/sensitivity scope.
    pub async fn get(
        &self,
        lease: &CacheLease,
    ) -> Result<Option<AdmittedCacheValue>, CacheStoreError> {
        let value = self
            .store
            .get_if_current(lease.scope(), lease.key(), lease.fence())
            .await?;
        if value.as_ref().is_some_and(|value| {
            value.classification() != lease.scope().classification()
                || value.is_sensitive() != lease.scope().is_sensitive()
        }) {
            return Err(CacheStoreError::ScopeMismatch);
        }
        Ok(value)
    }

    /// Conditionally stores a policy-admitted value under the lease's original fence.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free availability failure or [`CacheStoreError::ScopeMismatch`]
    /// when the admitted value does not exactly match the lease classification/sensitivity.
    pub async fn put(
        &self,
        lease: &CacheLease,
        value: AdmittedCacheValue,
    ) -> Result<CacheWriteOutcome, CacheStoreError> {
        if value.classification() != lease.scope().classification()
            || value.is_sensitive() != lease.scope().is_sensitive()
        {
            return Err(CacheStoreError::ScopeMismatch);
        }
        self.store
            .put_if_current(lease.scope(), lease.key(), lease.fence(), value)
            .await
    }

    /// Atomically advances a semantic or deletion fence and purges the scope.
    ///
    /// # Errors
    ///
    /// Returns [`CacheStoreError::FenceConflict`] before adapter invocation for a non-monotonic
    /// fence, or the adapter's conflict/availability failure.
    pub async fn invalidate(
        &self,
        scope: &CacheSecurityScope,
        expected_fence: CacheFence,
        next_fence: CacheFence,
    ) -> Result<CacheFence, CacheStoreError> {
        if !next_fence.strictly_advances(expected_fence) {
            return Err(CacheStoreError::FenceConflict);
        }
        self.store
            .advance_fence_and_delete(scope, expected_fence, next_fence)
            .await
    }
}

/// Provider prompt-cache request mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCacheMode {
    /// Do not request provider prompt caching.
    Disabled,
    /// Use provider caching only when exact capability evidence exists.
    Preferred,
    /// Fail admission rather than silently dropping provider cache controls.
    Required,
}

/// Explicit provider cache breakpoint over already-separated channels.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderCacheBreakpoint {
    /// Cache after trusted system instructions.
    System,
    /// Cache after trusted developer instructions.
    Developer,
    /// Cache after deterministic untrusted context data.
    Context,
    /// Cache after versioned tool definitions.
    Tools,
}

/// Provider cache route policy independent of application response caching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCachePolicy {
    mode: ProviderCacheMode,
    ttl_seconds: u64,
    breakpoints: BTreeSet<ProviderCacheBreakpoint>,
}

impl ProviderCachePolicy {
    /// Creates bounded provider-cache policy.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderCacheError::InvalidPolicy`] for zero/oversized TTLs or controls while disabled.
    pub fn new(
        mode: ProviderCacheMode,
        ttl_seconds: u64,
        breakpoints: BTreeSet<ProviderCacheBreakpoint>,
    ) -> Result<Self, ProviderCacheError> {
        if ttl_seconds == 0
            || ttl_seconds > MAX_PROVIDER_CACHE_TTL_SECONDS
            || (mode == ProviderCacheMode::Disabled && !breakpoints.is_empty())
        {
            return Err(ProviderCacheError::InvalidPolicy);
        }
        Ok(Self {
            mode,
            ttl_seconds,
            breakpoints,
        })
    }
}

/// Evidence-bound controls safe to pass to a provider adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCacheControls {
    model_key: ModelCapabilityKey,
    ttl_seconds: u64,
    breakpoints: BTreeSet<ProviderCacheBreakpoint>,
    capability_evidence_digest: ContentDigest,
}

impl ProviderCacheControls {
    /// Borrows the exact provider/model/revision identity admitted by the evidence.
    #[must_use]
    pub const fn model_key(&self) -> &ModelCapabilityKey {
        &self.model_key
    }

    /// Returns the explicit provider TTL.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// Borrows explicit cache breakpoints.
    #[must_use]
    pub const fn breakpoints(&self) -> &BTreeSet<ProviderCacheBreakpoint> {
        &self.breakpoints
    }

    /// Returns the exact evidence digest that admitted controls.
    #[must_use]
    pub const fn capability_evidence_digest(&self) -> ContentDigest {
        self.capability_evidence_digest
    }
}

/// Provider cache admission result with no implicit downgrade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderCacheAdmission {
    /// Provider caching was explicitly disabled by route policy.
    Disabled,
    /// Preferred caching was unavailable; no controls may be sent.
    Unavailable,
    /// Both prompt caching and explicit cache controls had exact capability evidence.
    Enabled(ProviderCacheControls),
}

/// Admits provider cache controls only from exact model capability evidence.
///
/// # Errors
///
/// Returns [`ProviderCacheError::RequiredCapabilityMissing`] for `Required` policy rather than
/// silently sending a downgraded request.
pub fn admit_provider_cache(
    policy: &ProviderCachePolicy,
    declaration: &ModelCapabilityDeclaration,
) -> Result<ProviderCacheAdmission, ProviderCacheError> {
    if policy.mode == ProviderCacheMode::Disabled {
        return Ok(ProviderCacheAdmission::Disabled);
    }
    let prompt_cache = declaration.evidence().get(&ModelCapability::PromptCaching);
    let cache_controls = declaration.evidence().get(&ModelCapability::CacheControls);
    let (Some(prompt_cache), Some(cache_controls)) = (prompt_cache, cache_controls) else {
        return if policy.mode == ProviderCacheMode::Required {
            Err(ProviderCacheError::RequiredCapabilityMissing)
        } else {
            Ok(ProviderCacheAdmission::Unavailable)
        };
    };
    let mut evidence = Vec::with_capacity(256);
    append_part(&mut evidence, declaration.key().provider().as_bytes());
    append_part(&mut evidence, declaration.key().model().as_bytes());
    append_part(&mut evidence, declaration.key().revision().as_bytes());
    append_part(&mut evidence, declaration.registry_revision().as_bytes());
    evidence.push(prompt_cache.source() as u8);
    append_part(&mut evidence, prompt_cache.revision().as_bytes());
    evidence.push(cache_controls.source() as u8);
    append_part(&mut evidence, cache_controls.revision().as_bytes());
    Ok(ProviderCacheAdmission::Enabled(ProviderCacheControls {
        model_key: declaration.key().clone(),
        ttl_seconds: policy.ttl_seconds,
        breakpoints: policy.breakpoints.clone(),
        capability_evidence_digest: ContentDigest::of(&evidence),
    }))
}

/// Value-free cache-key construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheKeyError {
    /// A tool or schema revision set exceeded its fixed boundary.
    #[error("cache dependency revisions exceed their limit")]
    TooManyRevisions,
}

/// Value-free application cache policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CachePolicyError {
    /// Cache byte limits were zero or exceeded hard ceilings.
    #[error("application cache limits are invalid")]
    InvalidLimits,
    /// Application caching was explicitly disabled.
    #[error("application caching is disabled")]
    Disabled,
    /// The independent value classification was not admitted.
    #[error("cache value classification is not admitted")]
    Classification,
    /// Sensitive content was not explicitly admitted.
    #[error("sensitive cache content is not admitted")]
    Sensitive,
    /// Normalized value bytes exceeded the configured limit.
    #[error("cache value exceeds its limit")]
    ValueLimit,
}

/// Value-free application cache adapter failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheStoreError {
    /// The cache was unavailable.
    #[error("application cache is unavailable")]
    Unavailable,
    /// The expected fence lost an invalidation race or did not advance monotonically.
    #[error("application cache fence conflict")]
    FenceConflict,
    /// A stored or submitted value did not match its classification/sensitivity key scope.
    #[error("application cache value does not match its security scope")]
    ScopeMismatch,
}

/// Value-free provider cache policy or capability failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderCacheError {
    /// Provider cache policy had an invalid TTL or disabled controls.
    #[error("provider cache policy is invalid")]
    InvalidPolicy,
    /// Required prompt caching and explicit controls lacked exact capability evidence.
    #[error("required provider cache capability is unavailable")]
    RequiredCapabilityMissing,
}

fn append_part(output: &mut Vec<u8>, value: &[u8]) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}
