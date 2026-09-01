use std::{fmt, io, sync::Arc};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    AvailabilitySnapshot, CapabilityInvocation, CapabilityKey, ConfirmationEvidence, Exposure,
    IdempotencyKey, InvocationContext,
};
use omnius_authz_basic::Decision;
use omnius_llm_prompt_catalog::{ContentDigest, PromptId, PromptRevisionNumber, RenderedPrompt};
use omnius_mcp_server_core::{
    McpDispatch, McpDispatchErrorCode, McpDispatchRequest, McpKernel, McpPrimitive,
    McpRequestContext,
};
use serde::{Serialize, Serializer, ser::SerializeMap as _};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};

use crate::{
    CacheControl, CacheScope, CatalogEtag, CatalogRevision, MCP_PROMPTS_PROTOCOL_REVISION,
    PromptMetadata, PromptProjectionCatalog, PublicPromptName,
};

/// Adapter metadata key for the bounded opaque catalog revision.
pub const META_CATALOG_REVISION: &str = "io.omnius.mcp/catalogRevision";
/// Adapter metadata key for the quoted visibility-sensitive catalog `ETag`.
pub const META_CATALOG_ETAG: &str = "io.omnius.mcp/catalogEtag";
/// Adapter metadata key for the cache TTL in milliseconds.
pub const META_TTL_MS: &str = "io.omnius.mcp/ttlMs";
/// Adapter metadata key for the `public` or `private` cache scope.
pub const META_CACHE_SCOPE: &str = "io.omnius.mcp/cacheScope";
/// Adapter metadata key for the canonical cache-control value.
pub const META_CACHE_CONTROL: &str = "io.omnius.mcp/cacheControl";

/// Discovery or retrieval action presented to the narrow authorization port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptAuthorizationAction {
    /// Authorization for discovery without prompt content.
    Discover,
    /// Authorization for retrieval and canonical capability invocation.
    Get,
}

/// Exact immutable prompt identity presented to the narrow authorization port.
#[derive(Clone, Copy)]
pub struct PromptAuthorizationTarget<'prompt> {
    public_name: &'prompt PublicPromptName,
    prompt_id: &'prompt PromptId,
    prompt_revision: PromptRevisionNumber,
    prompt_digest: ContentDigest,
    capability: &'prompt CapabilityKey,
}

impl<'prompt> PromptAuthorizationTarget<'prompt> {
    fn from_metadata(metadata: &'prompt PromptMetadata) -> Self {
        Self {
            public_name: metadata.public_name(),
            prompt_id: metadata.prompt_id(),
            prompt_revision: metadata.prompt_revision(),
            prompt_digest: metadata.prompt_digest(),
            capability: metadata.capability(),
        }
    }

    /// Borrows the exact stable public prompt name.
    #[must_use]
    pub const fn public_name(self) -> &'prompt PublicPromptName {
        self.public_name
    }

    /// Borrows the exact prompt-catalog identifier.
    #[must_use]
    pub const fn prompt_id(self) -> &'prompt PromptId {
        self.prompt_id
    }

    /// Returns the exact immutable prompt revision.
    #[must_use]
    pub const fn prompt_revision(self) -> PromptRevisionNumber {
        self.prompt_revision
    }

    /// Returns the exact immutable content digest.
    #[must_use]
    pub const fn prompt_digest(self) -> ContentDigest {
        self.prompt_digest
    }

    /// Borrows the exact canonical capability revision.
    #[must_use]
    pub const fn capability(self) -> &'prompt CapabilityKey {
        self.capability
    }
}

impl fmt::Debug for PromptAuthorizationTarget<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptAuthorizationTarget([redacted])")
    }
}

/// A fixed decision returned by the prompt discovery authorization port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptAuthorizationDecision {
    /// The exact capability projection is visible for this request context.
    Authorized,
    /// The projection must remain indistinguishable from an absent entry.
    Denied,
}

/// A redacted failure from the narrow prompt authorization port.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PromptAuthorizationError;

impl PromptAuthorizationError {
    /// Creates the sole fixed authorization-port failure.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self
    }
}

impl fmt::Debug for PromptAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptAuthorizationError([redacted])")
    }
}

impl fmt::Display for PromptAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP prompt authorization is unavailable")
    }
}

impl std::error::Error for PromptAuthorizationError {}

/// Narrow asynchronous authorization port used only for prompt discovery and retrieval.
///
/// This port cannot execute a prompt or replace the canonical capability registry.
#[async_trait]
pub trait PromptAuthorizer: Send + Sync {
    /// Authorizes one exact prompt and capability projection for the canonical context.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`PromptAuthorizationError`] when authorization cannot be evaluated.
    async fn authorize(
        &self,
        context: &InvocationContext,
        target: PromptAuthorizationTarget<'_>,
        action: PromptAuthorizationAction,
    ) -> Result<PromptAuthorizationDecision, PromptAuthorizationError>;
}

/// Stable public prompt-projection failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptProjectionErrorCode {
    /// Arguments or canonical invocation guardrail evidence were invalid.
    InvalidRequest,
    /// The name, extension declaration, or authorization decision rejected the request.
    Rejected,
    /// Authorization or canonical capability execution is temporarily unavailable.
    Unavailable,
    /// A non-caller-actionable internal projection failure occurred.
    Internal,
}

/// A fixed, redacted public prompt-projection failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PromptProjectionError {
    code: PromptProjectionErrorCode,
}

impl PromptProjectionError {
    const fn invalid_request() -> Self {
        Self {
            code: PromptProjectionErrorCode::InvalidRequest,
        }
    }

    const fn rejected() -> Self {
        Self {
            code: PromptProjectionErrorCode::Rejected,
        }
    }

    const fn unavailable() -> Self {
        Self {
            code: PromptProjectionErrorCode::Unavailable,
        }
    }

    const fn internal() -> Self {
        Self {
            code: PromptProjectionErrorCode::Internal,
        }
    }

    /// Returns the fixed public failure category.
    #[must_use]
    pub const fn code(self) -> PromptProjectionErrorCode {
        self.code
    }
}

impl fmt::Debug for PromptProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptProjectionError([redacted])")
    }
}

impl fmt::Display for PromptProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP prompt projection failed")
    }
}

impl std::error::Error for PromptProjectionError {}

/// Visibility-sensitive metadata for one authorized deterministic prompt list.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedListMetadata<'catalog> {
    catalog_revision: &'catalog CatalogRevision,
    catalog_etag: CatalogEtag,
    cache_control: &'catalog CacheControl,
}

impl AuthorizedListMetadata<'_> {
    /// Borrows the bounded opaque catalog revision.
    #[must_use]
    pub const fn catalog_revision(&self) -> &CatalogRevision {
        self.catalog_revision
    }

    /// Borrows the quoted `ETag` derived from the revision and exact visible ordered list.
    #[must_use]
    pub const fn catalog_etag(&self) -> &CatalogEtag {
        &self.catalog_etag
    }

    /// Returns the prevalidated TTL in milliseconds.
    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.cache_control.ttl_ms()
    }

    /// Returns the explicit cache scope.
    #[must_use]
    pub const fn cache_scope(&self) -> CacheScope {
        self.cache_control.scope()
    }

    /// Borrows prevalidated canonical cache control.
    #[must_use]
    pub const fn cache_control(&self) -> &CacheControl {
        self.cache_control
    }
}

impl Serialize for AuthorizedListMetadata<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry(META_CATALOG_REVISION, self.catalog_revision)?;
        map.serialize_entry(META_CATALOG_ETAG, &self.catalog_etag)?;
        map.serialize_entry(META_TTL_MS, &self.cache_control.ttl_ms())?;
        map.serialize_entry(META_CACHE_SCOPE, &self.cache_control.scope())?;
        map.serialize_entry(META_CACHE_CONTROL, self.cache_control.as_str())?;
        map.end()
    }
}

impl fmt::Debug for AuthorizedListMetadata<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedListMetadata([redacted])")
    }
}

/// An authorization-filtered deterministic prompt discovery result.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct AuthorizedPromptList<'catalog> {
    prompts: Vec<PromptMetadata>,
    #[serde(rename = "_meta")]
    metadata: AuthorizedListMetadata<'catalog>,
}

impl AuthorizedPromptList<'_> {
    /// Borrows visible prompts in stable public-name order.
    #[must_use]
    pub fn prompts(&self) -> &[PromptMetadata] {
        &self.prompts
    }

    /// Borrows visibility-sensitive `_meta` concepts for an adapter.
    #[must_use]
    pub const fn metadata(&self) -> &AuthorizedListMetadata<'_> {
        &self.metadata
    }
}

impl fmt::Debug for AuthorizedPromptList<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedPromptList([redacted])")
    }
}

/// Canonical request context, arguments, and registry guardrail evidence for one retrieval.
pub struct PromptGetRequest {
    request_context: McpRequestContext,
    public_name: PublicPromptName,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
    arguments: Value,
}

impl PromptGetRequest {
    /// Creates a transport-independent retrieval request from one canonical MCP request context.
    #[must_use]
    pub fn new(
        request_context: McpRequestContext,
        public_name: PublicPromptName,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<IdempotencyKey>,
        arguments: Value,
    ) -> Self {
        Self {
            request_context,
            public_name,
            confirmation,
            idempotency_key,
            arguments,
        }
    }
}

impl fmt::Debug for PromptGetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptGetRequest([redacted])")
    }
}

/// A non-forgeable view of a rendered privileged system instruction.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrivilegedSystemInstruction<'prompt>(&'prompt str);

impl<'prompt> PrivilegedSystemInstruction<'prompt> {
    /// Borrows trusted system instruction text.
    #[must_use]
    pub const fn as_str(self) -> &'prompt str {
        self.0
    }
}

impl fmt::Debug for PrivilegedSystemInstruction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivilegedSystemInstruction([redacted])")
    }
}

/// A non-forgeable view of a rendered privileged developer instruction.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrivilegedDeveloperInstruction<'prompt>(&'prompt str);

impl<'prompt> PrivilegedDeveloperInstruction<'prompt> {
    /// Borrows trusted developer instruction text.
    #[must_use]
    pub const fn as_str(self) -> &'prompt str {
        self.0
    }
}

impl fmt::Debug for PrivilegedDeveloperInstruction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivilegedDeveloperInstruction([redacted])")
    }
}

/// A non-forgeable view of the rendered user channel containing only untrusted data.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UntrustedUserContent<'prompt>(&'prompt str);

impl<'prompt> UntrustedUserContent<'prompt> {
    /// Borrows untrusted rendered user content.
    #[must_use]
    pub const fn as_str(self) -> &'prompt str {
        self.0
    }
}

impl fmt::Debug for UntrustedUserContent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UntrustedUserContent([redacted])")
    }
}

/// Separately typed rendered channels with no concatenation operation.
#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalPrompt {
    rendered: RenderedPrompt,
}

impl CanonicalPrompt {
    fn from_rendered(rendered: RenderedPrompt) -> Self {
        Self { rendered }
    }

    /// Borrows the optional privileged system channel.
    #[must_use]
    pub fn system(&self) -> Option<PrivilegedSystemInstruction<'_>> {
        self.rendered
            .system()
            .map(|instruction| PrivilegedSystemInstruction(instruction.as_str()))
    }

    /// Borrows the optional privileged developer channel.
    #[must_use]
    pub fn developer(&self) -> Option<PrivilegedDeveloperInstruction<'_>> {
        self.rendered
            .developer()
            .map(|instruction| PrivilegedDeveloperInstruction(instruction.as_str()))
    }

    /// Borrows the required untrusted user channel.
    #[must_use]
    pub fn user(&self) -> UntrustedUserContent<'_> {
        UntrustedUserContent(self.rendered.user().as_str())
    }
}

impl Serialize for CanonicalPrompt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = 1
            + usize::from(self.rendered.system().is_some())
            + usize::from(self.rendered.developer().is_some());
        let mut map = serializer.serialize_map(Some(field_count))?;
        if let Some(system) = self.system() {
            map.serialize_entry("system", &system)?;
        }
        if let Some(developer) = self.developer() {
            map.serialize_entry("developer", &developer)?;
        }
        map.serialize_entry("user", &self.user())?;
        map.end()
    }
}

impl fmt::Debug for CanonicalPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalPrompt([redacted])")
    }
}

/// Protocol-independent canonical result for future MCP result adapters.
///
/// The domain result intentionally contains no RMCP value or current-protocol
/// result discriminator. Adapters may map it to any negotiated wire revision.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalPromptResult<'catalog> {
    metadata: &'catalog PromptMetadata,
    prompt: CanonicalPrompt,
}

impl CanonicalPromptResult<'_> {
    /// Borrows exact public, schema, capability, revision, and digest metadata.
    #[must_use]
    pub const fn metadata(&self) -> &PromptMetadata {
        self.metadata
    }

    /// Borrows separately typed privileged and untrusted rendered channels.
    #[must_use]
    pub const fn prompt(&self) -> &CanonicalPrompt {
        &self.prompt
    }
}

impl fmt::Debug for CanonicalPromptResult<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalPromptResult([redacted])")
    }
}

/// Canonical prompt projection over one immutable catalog and canonical MCP dispatch.
pub struct McpPromptProjection<A: PromptAuthorizer + ?Sized> {
    catalog: Arc<PromptProjectionCatalog>,
    kernel: Arc<McpKernel>,
    dispatch: Arc<dyn McpDispatch>,
    authorizer: Arc<A>,
}

impl<A: PromptAuthorizer + ?Sized> McpPromptProjection<A> {
    /// Creates a projection backed by one concrete [`McpKernel`].
    ///
    /// # Errors
    ///
    /// Returns a fixed internal error if the kernel does not implement the pinned
    /// `2026-07-28` revision or any catalog capability lacks MCP-prompt exposure.
    pub fn new(
        catalog: Arc<PromptProjectionCatalog>,
        kernel: Arc<McpKernel>,
        authorizer: Arc<A>,
    ) -> Result<Self, PromptProjectionError> {
        let dispatch: Arc<dyn McpDispatch> = kernel.clone();
        Self::with_dispatch(catalog, kernel, dispatch, authorizer)
    }

    /// Creates a projection with an explicit object-safe canonical dispatch contribution.
    ///
    /// The kernel remains the immutable metadata and availability authority. Invocation is
    /// performed only through `dispatch`.
    ///
    /// # Errors
    ///
    /// Returns a fixed internal error if the kernel does not implement the pinned
    /// protocol revision or any catalog capability lacks MCP-prompt exposure.
    pub fn with_dispatch(
        catalog: Arc<PromptProjectionCatalog>,
        kernel: Arc<McpKernel>,
        dispatch: Arc<dyn McpDispatch>,
        authorizer: Arc<A>,
    ) -> Result<Self, PromptProjectionError> {
        if kernel.protocol_revision() != MCP_PROMPTS_PROTOCOL_REVISION {
            return Err(PromptProjectionError::internal());
        }
        if catalog.entries.values().any(|definition| {
            kernel
                .document(definition.metadata.capability())
                .is_none_or(|document| !document.exposures.contains(&Exposure::McpPrompt))
        }) {
            return Err(PromptProjectionError::internal());
        }
        Ok(Self {
            catalog,
            kernel,
            dispatch,
            authorizer,
        })
    }

    /// Lists only currently available entries whose exact required extensions are negotiated
    /// and whose backing capability supports the request's selected tenant mode.
    ///
    /// The result is ordered by stable public name. Its `ETag` binds the catalog
    /// revision and exact serialized visible list, so authorization differences
    /// cannot reuse metadata for a different list. A deprecated replacement name
    /// is removed unless that target is also visible. A canonical context that is
    /// not explicitly allowed returns an empty list without consulting the custom
    /// authorization port.
    ///
    /// # Errors
    ///
    /// Returns a fixed unavailable error when authorization cannot be evaluated,
    /// or a fixed internal error if deterministic metadata serialization fails.
    pub async fn list<'catalog>(
        &'catalog self,
        request: &McpRequestContext,
    ) -> Result<AuthorizedPromptList<'catalog>, PromptProjectionError> {
        let canonical = request.canonical();
        let context = canonical.invocation();
        if context.authorization() != Decision::Allow {
            return finish_list(&self.catalog, Vec::new());
        }
        let availability = self.kernel.availability_snapshot();
        let negotiated_extensions = request.negotiated_extensions();
        let tenant_mode = canonical.tenant_mode();
        let mut authorized = Vec::with_capacity(self.catalog.entries.len());
        for definition in self.catalog.entries.values() {
            let tenant_mode_is_supported = self
                .kernel
                .document(definition.metadata.capability())
                .is_some_and(|document| document.tenant_modes.binary_search(&tenant_mode).is_ok());
            if !definition
                .metadata
                .required_extensions()
                .iter()
                .all(|extension| negotiated_extensions.contains(extension))
                || !tenant_mode_is_supported
                || !capability_is_available(&availability, definition.metadata.capability())
            {
                continue;
            }
            match self
                .authorizer
                .authorize(
                    context,
                    PromptAuthorizationTarget::from_metadata(&definition.metadata),
                    PromptAuthorizationAction::Discover,
                )
                .await
                .map_err(|_| PromptProjectionError::unavailable())?
            {
                PromptAuthorizationDecision::Authorized => {
                    authorized.push(&definition.metadata);
                }
                PromptAuthorizationDecision::Denied => {}
            }
        }
        let prompts = authorized
            .iter()
            .map(|metadata| {
                let replacement_visible =
                    metadata
                        .compatibility()
                        .replacement()
                        .is_none_or(|replacement| {
                            authorized
                                .binary_search_by(|candidate| {
                                    candidate.public_name().cmp(replacement)
                                })
                                .is_ok()
                        });
                metadata.visible_clone(replacement_visible)
            })
            .collect();
        finish_list(&self.catalog, prompts)
    }

    /// Validates, renders, and invokes one exact published prompt projection.
    ///
    /// Canonical context denial is checked before name lookup, exact extension eligibility,
    /// the narrow authorization port, argument validation, or rendering. Arguments are then
    /// size/schema validated and rendered by the renderer
    /// compiled for the exact immutable catalog revision. Only after successful
    /// rendering is a canonical [`CapabilityInvocation`] sent through the object-safe
    /// [`McpDispatch`] contribution as [`McpPrimitive::Prompt`]. The rendered result is
    /// returned only after that canonical dispatch succeeds.
    ///
    /// # Errors
    ///
    /// Returns only fixed, redacted [`PromptProjectionError`] categories.
    pub async fn get(
        &self,
        request: PromptGetRequest,
    ) -> Result<CanonicalPromptResult<'_>, PromptProjectionError> {
        let PromptGetRequest {
            request_context,
            public_name,
            confirmation,
            idempotency_key,
            arguments,
        } = request;
        let canonical = request_context.canonical();
        if canonical.invocation().authorization() != Decision::Allow {
            return Err(PromptProjectionError::rejected());
        }
        let definition = self
            .catalog
            .entries
            .get(&public_name)
            .ok_or(PromptProjectionError::rejected())?;
        if !definition
            .metadata
            .required_extensions()
            .iter()
            .all(|extension| request_context.negotiated_extensions().contains(extension))
        {
            return Err(PromptProjectionError::rejected());
        }
        if self
            .authorizer
            .authorize(
                canonical.invocation(),
                PromptAuthorizationTarget::from_metadata(&definition.metadata),
                PromptAuthorizationAction::Get,
            )
            .await
            .map_err(|_| PromptProjectionError::unavailable())?
            != PromptAuthorizationDecision::Authorized
        {
            return Err(PromptProjectionError::rejected());
        }
        let rendered = definition
            .renderer
            .render(&arguments)
            .map_err(|_| PromptProjectionError::invalid_request())?;
        let invocation = CapabilityInvocation::new(
            definition.metadata.capability().clone(),
            canonical.invocation().clone(),
            canonical.tenant_mode(),
            invocation_input(&definition.metadata, arguments),
            confirmation,
            idempotency_key,
        );
        self.dispatch
            .dispatch(McpDispatchRequest::new(
                request_context.metadata().clone(),
                McpPrimitive::Prompt,
                invocation,
            ))
            .await
            .map_err(|error| from_dispatch_error(error.code()))?;
        Ok(CanonicalPromptResult {
            metadata: &definition.metadata,
            prompt: CanonicalPrompt::from_rendered(rendered),
        })
    }
}

impl<A: PromptAuthorizer + ?Sized> fmt::Debug for McpPromptProjection<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpPromptProjection([redacted])")
    }
}

fn invocation_input(metadata: &PromptMetadata, arguments: Value) -> Value {
    let mut input = Map::new();
    input.insert("arguments".to_owned(), arguments);
    input.insert(
        "prompt_digest".to_owned(),
        Value::String(metadata.prompt_digest().to_hex()),
    );
    input.insert(
        "prompt_id".to_owned(),
        Value::String(metadata.prompt_id().as_str().to_owned()),
    );
    input.insert(
        "prompt_revision".to_owned(),
        Value::Number(Number::from(metadata.prompt_revision().get())),
    );
    Value::Object(input)
}
fn capability_is_available(snapshot: &AvailabilitySnapshot, capability: &CapabilityKey) -> bool {
    snapshot
        .capabilities()
        .binary_search_by(|status| status.capability().cmp(capability))
        .is_ok_and(|index| {
            let status = &snapshot.capabilities()[index];
            status.compiled() && status.runtime().is_available()
        })
}

fn finish_list(
    catalog: &PromptProjectionCatalog,
    prompts: Vec<PromptMetadata>,
) -> Result<AuthorizedPromptList<'_>, PromptProjectionError> {
    let catalog_etag = visible_etag(&catalog.revision, &prompts)?;
    Ok(AuthorizedPromptList {
        prompts,
        metadata: AuthorizedListMetadata {
            catalog_revision: &catalog.revision,
            catalog_etag,
            cache_control: &catalog.cache_control,
        },
    })
}

struct DigestWriter<'a>(&'a mut Sha256);

impl io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn visible_etag(
    revision: &CatalogRevision,
    prompts: &[PromptMetadata],
) -> Result<CatalogEtag, PromptProjectionError> {
    let mut hasher = Sha256::new();
    hasher.update(b"omnius.mcp.prompts.visible-catalog.v1\0");
    serde_json::to_writer(&mut DigestWriter(&mut hasher), &(revision, prompts))
        .map_err(|_| PromptProjectionError::internal())?;
    Ok(CatalogEtag::from_sha256(hasher.finalize().into()))
}

const fn from_dispatch_error(code: McpDispatchErrorCode) -> PromptProjectionError {
    match code {
        McpDispatchErrorCode::InvalidRequest => PromptProjectionError::invalid_request(),
        McpDispatchErrorCode::Rejected => PromptProjectionError::rejected(),
        McpDispatchErrorCode::Unavailable => PromptProjectionError::unavailable(),
        McpDispatchErrorCode::Internal => PromptProjectionError::internal(),
    }
}
