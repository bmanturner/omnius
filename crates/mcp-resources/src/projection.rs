use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use omnius_agent_capability_registry::{
    CapabilityInvocation, ConfirmationEvidence, Exposure, IdempotencyKey, InvocationContext,
};
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::{
    McpDispatchErrorCode, McpDispatchRequest, McpExtension, McpKernel, McpPrimitive,
    McpRequestContext,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ByteRange, CacheControl, CacheScope, CatalogRevision, ExactResourceDeclaration, MimeType,
    OpaqueResourceValue, PublicResourceName, ResourceCacheMetadata, ResourceCatalog,
    ResourceCompatibility, ResourceContent, ResourceDescription, ResourceError, ResourceHierarchy,
    ResourceLimits, ResourceMetadata, ResourceObjectReference, ResourceProvenance,
    ResourceRangeResponse, ResourceResult, ResourceTemplateDeclaration, ResourceTitle, ResourceUri,
    ResourceUriTemplate, Sha256Digest, TenantBinding,
    catalog::ResolvedDeclaration,
    result::{
        RawCacheScope, RawHierarchy, RawObjectReference, RawRangeResponse, RawResourceContent,
        RawResourceResult,
    },
};
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

const MAX_HIERARCHY_CHILDREN: usize = 256;
const MAX_HIERARCHY_PAGE_SIZE: u16 = 256;

/// The authorization action evaluated for an exact declaration, template, or resolved read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceAuthorizationAction {
    /// Discover an exact resource.
    DiscoverResource,
    /// Discover a resource template.
    DiscoverTemplate,
    /// Read one resolved resource.
    Read,
    /// List hierarchy children through the internal canonical port.
    ListChildren,
}

/// The URI shape supplied to the narrow resource authorization port.
#[derive(Clone, Copy)]
pub enum ResourceAuthorizationUri<'a> {
    /// An exact catalog URI during discovery.
    Exact(&'a ResourceUri),
    /// A strict URI template during discovery.
    Template(&'a ResourceUriTemplate),
    /// A fully resolved request URI.
    Resolved(&'a ResourceUri),
}

/// A minimal immutable authorization target without content or registry output.
#[derive(Clone, Copy)]
pub struct ResourceAuthorizationTarget<'a> {
    name: &'a PublicResourceName,
    capability: &'a omnius_agent_capability_registry::CapabilityKey,
    schema_revision: &'a crate::SchemaRevision,
    uri: ResourceAuthorizationUri<'a>,
}

impl<'a> ResourceAuthorizationTarget<'a> {
    const fn new(
        metadata: &'a ResourceMetadata,
        capability: &'a omnius_agent_capability_registry::CapabilityKey,
        uri: ResourceAuthorizationUri<'a>,
    ) -> Self {
        Self {
            name: metadata.name(),
            capability,
            schema_revision: metadata.schema_revision(),
            uri,
        }
    }

    /// Returns the explicit stable public resource name.
    #[must_use]
    pub const fn name(self) -> &'a PublicResourceName {
        self.name
    }

    /// Returns the canonical capability revision.
    #[must_use]
    pub const fn capability(self) -> &'a omnius_agent_capability_registry::CapabilityKey {
        self.capability
    }

    /// Returns the declared result schema revision.
    #[must_use]
    pub const fn schema_revision(self) -> &'a crate::SchemaRevision {
        self.schema_revision
    }

    /// Returns the exact, template, or resolved URI authorization target.
    #[must_use]
    pub const fn uri(self) -> ResourceAuthorizationUri<'a> {
        self.uri
    }
}

/// Narrow asynchronous policy port used only for resource discovery and resolved reads.
#[async_trait]
pub trait ResourceAuthorizer: Send + Sync {
    /// Returns a fail-closed authorization decision for one candidate or resolved target.
    async fn authorize(
        &self,
        context: &InvocationContext,
        action: ResourceAuthorizationAction,
        target: ResourceAuthorizationTarget<'_>,
    ) -> Decision;
}

/// One authorized exact-resource list entry in stable public-name order.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct AuthorizedResource {
    name: PublicResourceName,
    title: ResourceTitle,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<ResourceDescription>,
    uri: ResourceUri,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<MimeType>,
    schema_revision: crate::SchemaRevision,
    compatibility: ResourceCompatibility,
}

impl AuthorizedResource {
    fn from_declaration(declaration: &ExactResourceDeclaration) -> Self {
        let metadata = declaration.metadata();
        Self {
            name: metadata.name().clone(),
            title: metadata.title().clone(),
            description: metadata.description().cloned(),
            uri: declaration.uri().clone(),
            mime_type: metadata.mime_type().cloned(),
            schema_revision: metadata.schema_revision().clone(),
            compatibility: metadata.compatibility().clone(),
        }
    }

    /// Returns the stable public name.
    #[must_use]
    pub const fn name(&self) -> &PublicResourceName {
        &self.name
    }
    /// Returns the human-readable title.
    #[must_use]
    pub const fn title(&self) -> &ResourceTitle {
        &self.title
    }
    /// Returns the optional description.
    #[must_use]
    pub const fn description(&self) -> Option<&ResourceDescription> {
        self.description.as_ref()
    }
    /// Returns the exact URI.
    #[must_use]
    pub const fn uri(&self) -> &ResourceUri {
        &self.uri
    }
    /// Returns the optional advertised MIME type.
    #[must_use]
    pub const fn mime_type(&self) -> Option<&MimeType> {
        self.mime_type.as_ref()
    }
    /// Returns the explicit schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> &crate::SchemaRevision {
        &self.schema_revision
    }
    /// Returns compatibility and deprecation metadata.
    #[must_use]
    pub const fn compatibility(&self) -> &ResourceCompatibility {
        &self.compatibility
    }
}

/// One authorized resource-template list entry in stable public-name order.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct AuthorizedResourceTemplate {
    name: PublicResourceName,
    title: ResourceTitle,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<ResourceDescription>,
    uri_template: ResourceUriTemplate,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<MimeType>,
    schema_revision: crate::SchemaRevision,
    compatibility: ResourceCompatibility,
}

impl AuthorizedResourceTemplate {
    fn from_declaration(declaration: &ResourceTemplateDeclaration) -> Self {
        let metadata = declaration.metadata();
        Self {
            name: metadata.name().clone(),
            title: metadata.title().clone(),
            description: metadata.description().cloned(),
            uri_template: declaration.uri_template().clone(),
            mime_type: metadata.mime_type().cloned(),
            schema_revision: metadata.schema_revision().clone(),
            compatibility: metadata.compatibility().clone(),
        }
    }

    /// Returns the stable public name.
    #[must_use]
    pub const fn name(&self) -> &PublicResourceName {
        &self.name
    }
    /// Returns the human-readable title.
    #[must_use]
    pub const fn title(&self) -> &ResourceTitle {
        &self.title
    }
    /// Returns the optional description.
    #[must_use]
    pub const fn description(&self) -> Option<&ResourceDescription> {
        self.description.as_ref()
    }
    /// Returns the strict URI template.
    #[must_use]
    pub const fn uri_template(&self) -> &ResourceUriTemplate {
        &self.uri_template
    }
    /// Returns the optional advertised MIME type.
    #[must_use]
    pub const fn mime_type(&self) -> Option<&MimeType> {
        self.mime_type.as_ref()
    }
    /// Returns the explicit schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> &crate::SchemaRevision {
        &self.schema_revision
    }
    /// Returns compatibility and deprecation metadata.
    #[must_use]
    pub const fn compatibility(&self) -> &ResourceCompatibility {
        &self.compatibility
    }
}

/// Visibility-sensitive `_meta` concepts for one authorized catalog view.
pub struct AuthorizedCatalogMetadata {
    catalog_revision: CatalogRevision,
    catalog_etag: Sha256Digest,
    cache_control: CacheControl,
}

impl AuthorizedCatalogMetadata {
    /// Returns the bounded immutable catalog revision.
    #[must_use]
    pub const fn catalog_revision(&self) -> &CatalogRevision {
        &self.catalog_revision
    }
    /// Returns the SHA-256 `ETag` derived from this exact ordered visible view.
    #[must_use]
    pub const fn catalog_etag(&self) -> &Sha256Digest {
        &self.catalog_etag
    }
    /// Returns the prevalidated private cache policy.
    #[must_use]
    pub const fn cache_control(&self) -> CacheControl {
        self.cache_control
    }

    /// Creates adapter-ready metadata with the exact reserved Omnius keys and values.
    #[must_use]
    pub fn adapter_meta(&self) -> BTreeMap<String, Value> {
        let ttl_ms = u64::from(self.cache_control.max_age_seconds()) * 1_000;
        BTreeMap::from([
            (
                "io.omnius.mcp/cacheControl".to_owned(),
                Value::String(self.cache_control.header_value()),
            ),
            (
                "io.omnius.mcp/cacheScope".to_owned(),
                Value::String("private".to_owned()),
            ),
            (
                "io.omnius.mcp/catalogEtag".to_owned(),
                Value::String(format!("\"{}\"", self.catalog_etag.as_str())),
            ),
            (
                "io.omnius.mcp/catalogRevision".to_owned(),
                Value::String(self.catalog_revision.as_str().to_owned()),
            ),
            ("io.omnius.mcp/ttlMs".to_owned(), Value::from(ttl_ms)),
        ])
    }
}

/// Deterministic, separately authorized exact-resource and resource-template lists.
pub struct AuthorizedResourceCatalog {
    resources: Vec<AuthorizedResource>,
    templates: Vec<AuthorizedResourceTemplate>,
    metadata: AuthorizedCatalogMetadata,
}

impl AuthorizedResourceCatalog {
    /// Returns exact resources in stable public-name order.
    #[must_use]
    pub fn resources(&self) -> &[AuthorizedResource] {
        &self.resources
    }
    /// Returns resource templates in stable public-name order.
    #[must_use]
    pub fn templates(&self) -> &[AuthorizedResourceTemplate] {
        &self.templates
    }
    /// Returns visibility-sensitive catalog `_meta` concepts.
    #[must_use]
    pub const fn metadata(&self) -> &AuthorizedCatalogMetadata {
        &self.metadata
    }
}

/// A hierarchy-ready canonical resource operation.
pub enum ResourceOperation {
    /// Read canonical content.
    Read,
    /// List bounded hierarchy children through the internal domain port.
    ListChildren {
        /// Maximum child count requested.
        limit: u16,
        /// Optional bounded opaque continuation cursor.
        cursor: Option<OpaqueResourceValue>,
    },
}

impl ResourceOperation {
    /// Creates a bounded hierarchy listing operation.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for a zero or excessive page size.
    pub fn list_children(
        limit: u16,
        cursor: Option<OpaqueResourceValue>,
    ) -> Result<Self, ResourceError> {
        if limit == 0 || limit > MAX_HIERARCHY_PAGE_SIZE {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self::ListChildren { limit, cursor })
    }
}

/// One owned canonical resource request, including all registry guardrail evidence.
pub struct ResourceRequest {
    request_context: McpRequestContext,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
    target: PublicResourceName,
    uri: ResourceUri,
    operation: ResourceOperation,
    range: Option<ByteRange>,
}

impl ResourceRequest {
    /// Creates a canonical resource request.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for a malformed hierarchy limit or a hierarchy/range mix.
    pub fn new(
        request_context: McpRequestContext,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<IdempotencyKey>,
        target: PublicResourceName,
        uri: ResourceUri,
        operation: ResourceOperation,
        range: Option<ByteRange>,
    ) -> Result<Self, ResourceError> {
        if let ResourceOperation::ListChildren { limit, .. } = &operation
            && (*limit == 0 || *limit > MAX_HIERARCHY_PAGE_SIZE || range.is_some())
        {
            return Err(ResourceError::invalid_request());
        }
        Ok(Self {
            request_context,
            confirmation,
            idempotency_key,
            target,
            uri,
            operation,
            range,
        })
    }
}

/// Canonical MCP resource projection over one immutable catalog and [`McpKernel`].
pub struct ResourceProjection {
    kernel: Arc<McpKernel>,
    catalog: Arc<ResourceCatalog>,
    authorizer: Arc<dyn ResourceAuthorizer>,
}

impl ResourceProjection {
    /// Creates a projection and verifies every catalog declaration against the kernel registry.
    ///
    /// # Errors
    ///
    /// Returns a redacted declaration error when catalog and registry metadata diverge.
    pub fn new(
        kernel: Arc<McpKernel>,
        catalog: Arc<ResourceCatalog>,
        authorizer: Arc<dyn ResourceAuthorizer>,
    ) -> Result<Self, ResourceError> {
        for (capability, tenant_mode) in catalog
            .exact_resources()
            .map(|declaration| (declaration.capability(), declaration.tenant_mode()))
            .chain(
                catalog
                    .resource_templates()
                    .map(|declaration| (declaration.capability(), declaration.tenant_mode())),
            )
        {
            let Some(document) = kernel.document(capability) else {
                return Err(ResourceError::invalid_declaration());
            };
            if !document.exposures.contains(&Exposure::McpResource)
                || !document.tenant_modes.contains(&tenant_mode)
            {
                return Err(ResourceError::invalid_declaration());
            }
        }
        Ok(Self {
            kernel,
            catalog,
            authorizer,
        })
    }

    /// Returns the immutable projection catalog.
    #[must_use]
    pub const fn catalog(&self) -> &Arc<ResourceCatalog> {
        &self.catalog
    }

    /// Builds deterministic separate authorized resource and template lists.
    ///
    /// Extension-ineligible and unauthorized entries are omitted entirely. The returned `ETag`
    /// hashes the catalog revision plus the exact serialized ordered visible lists.
    ///
    /// # Errors
    ///
    /// Returns a fixed internal error only if deterministic metadata encoding fails.
    pub async fn list_authorized(
        &self,
        request: &McpRequestContext,
    ) -> Result<AuthorizedResourceCatalog, ResourceError> {
        let canonical = request.canonical();
        let context = canonical.invocation();
        if !matches!(context.authorization(), Decision::Allow) {
            return self.finish_authorized_catalog(Vec::new(), Vec::new());
        }
        let selected_tenant_mode = canonical.tenant_mode();
        let availability = self.kernel.availability_snapshot();
        let mut resources = Vec::new();
        for declaration in self.catalog.exact_resources() {
            if declaration.tenant_mode() != selected_tenant_mode
                || !extensions_satisfied(request, declaration.metadata().required_extensions())
                || !capability_is_available(&availability, declaration.capability())
                || !exact_discovery_tenant_eligible(declaration, context)
            {
                continue;
            }
            let target = ResourceAuthorizationTarget::new(
                declaration.metadata(),
                declaration.capability(),
                ResourceAuthorizationUri::Exact(declaration.uri()),
            );
            if matches!(
                self.authorizer
                    .authorize(
                        context,
                        ResourceAuthorizationAction::DiscoverResource,
                        target
                    )
                    .await,
                Decision::Allow
            ) {
                resources.push(AuthorizedResource::from_declaration(declaration));
            }
        }
        let mut templates = Vec::new();
        for declaration in self.catalog.resource_templates() {
            if declaration.tenant_mode() != selected_tenant_mode
                || !extensions_satisfied(request, declaration.metadata().required_extensions())
                || !capability_is_available(&availability, declaration.capability())
                || !template_discovery_tenant_eligible(declaration, context)
            {
                continue;
            }
            let target = ResourceAuthorizationTarget::new(
                declaration.metadata(),
                declaration.capability(),
                ResourceAuthorizationUri::Template(declaration.uri_template()),
            );
            if matches!(
                self.authorizer
                    .authorize(
                        context,
                        ResourceAuthorizationAction::DiscoverTemplate,
                        target
                    )
                    .await,
                Decision::Allow
            ) {
                templates.push(AuthorizedResourceTemplate::from_declaration(declaration));
            }
        }
        let visible_names = resources
            .iter()
            .map(|resource| resource.name.as_str().to_owned())
            .chain(
                templates
                    .iter()
                    .map(|template| template.name.as_str().to_owned()),
            )
            .collect::<BTreeSet<_>>();
        for resource in &mut resources {
            hide_ineligible_replacement(&mut resource.compatibility, &visible_names);
        }
        for template in &mut templates {
            hide_ineligible_replacement(&mut template.compatibility, &visible_names);
        }
        self.finish_authorized_catalog(resources, templates)
    }

    fn finish_authorized_catalog(
        &self,
        resources: Vec<AuthorizedResource>,
        templates: Vec<AuthorizedResourceTemplate>,
    ) -> Result<AuthorizedResourceCatalog, ResourceError> {
        let digest_input = serde_json::to_vec(&(
            self.catalog.revision(),
            resources.as_slice(),
            templates.as_slice(),
        ))
        .map_err(|_| ResourceError::internal())?;
        Ok(AuthorizedResourceCatalog {
            resources,
            templates,
            metadata: AuthorizedCatalogMetadata {
                catalog_revision: self.catalog.revision().clone(),
                catalog_etag: digest_bytes(&digest_input),
                cache_control: self.catalog.list_cache_control(),
            },
        })
    }

    /// Reads one resource exclusively through the canonical kernel boundary.
    ///
    /// # Errors
    ///
    /// Returns a fixed invalid-request error for a hierarchy operation, or the redacted
    /// execution error returned by [`Self::execute`].
    pub async fn read(&self, request: ResourceRequest) -> Result<ResourceResult, ResourceError> {
        if !matches!(&request.operation, ResourceOperation::Read) {
            return Err(ResourceError::invalid_request());
        }
        self.execute(request).await
    }

    /// Executes a read or hierarchy request exclusively through [`McpKernel::invoke`].
    ///
    /// # Errors
    ///
    /// Returns only fixed redacted projection errors.
    pub async fn execute(&self, request: ResourceRequest) -> Result<ResourceResult, ResourceError> {
        let canonical = request.request_context.canonical();
        let context = canonical.invocation();
        if !matches!(context.authorization(), Decision::Allow) {
            return Err(ResourceError::rejected());
        }
        let resolved = self
            .catalog
            .resolve(&request.target, &request.uri)
            .ok_or_else(ResourceError::rejected)?;
        let declaration = &resolved.declaration;
        if !extensions_satisfied(
            &request.request_context,
            declaration.metadata().required_extensions(),
        ) || canonical.tenant_mode() != declaration.tenant_mode()
            || !tenant_binding_satisfied(
                declaration.tenant_binding(),
                &request.uri,
                &resolved.variables,
                context,
            )
        {
            return Err(ResourceError::rejected());
        }
        let action = match &request.operation {
            ResourceOperation::Read => ResourceAuthorizationAction::Read,
            ResourceOperation::ListChildren { .. } => ResourceAuthorizationAction::ListChildren,
        };
        let target = ResourceAuthorizationTarget::new(
            declaration.metadata(),
            declaration.capability(),
            ResourceAuthorizationUri::Resolved(&request.uri),
        );
        if !matches!(
            self.authorizer.authorize(context, action, target).await,
            Decision::Allow
        ) {
            return Err(ResourceError::rejected());
        }
        if let Some(range) = request.range {
            let Some(max_range) = declaration.limits().max_range_bytes() else {
                return Err(ResourceError::invalid_request());
            };
            if range.length() > max_range
                || range.length() > declaration.limits().max_content_bytes()
            {
                return Err(ResourceError::invalid_request());
            }
        }
        let expected_tenant = context.tenant_id().map(|tenant| tenant.to_string());
        let input = canonical_input(
            self.catalog.revision(),
            declaration.metadata(),
            &request.uri,
            &resolved.variables,
            &request.request_context,
            &request.operation,
            request.range,
        );
        let metadata = request.request_context.metadata().clone();
        let invocation_context = context.clone();
        let tenant_mode = canonical.tenant_mode();
        let invocation = CapabilityInvocation::new(
            declaration.capability().clone(),
            invocation_context,
            tenant_mode,
            input,
            request.confirmation,
            request.idempotency_key,
        );
        let output = self
            .kernel
            .invoke(McpDispatchRequest::new(
                metadata,
                McpPrimitive::Resource,
                invocation,
            ))
            .await
            .map_err(|error| match error.code() {
                McpDispatchErrorCode::InvalidRequest => ResourceError::invalid_request(),
                McpDispatchErrorCode::Rejected => ResourceError::rejected(),
                McpDispatchErrorCode::Unavailable => ResourceError::unavailable(),
                McpDispatchErrorCode::Internal => ResourceError::internal(),
            })?
            .into_output();
        self.decode_output(
            output,
            &request.target,
            &request.uri,
            declaration,
            request.range,
            &request.operation,
            expected_tenant.as_deref(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "decoding validates each independent request/result invariant in one boundary"
    )]
    fn decode_output(
        &self,
        output: Value,
        target: &PublicResourceName,
        requested_uri: &ResourceUri,
        declaration: &ResolvedDeclaration<'_>,
        requested_range: Option<ByteRange>,
        operation: &ResourceOperation,
        expected_tenant: Option<&str>,
    ) -> Result<ResourceResult, ResourceError> {
        let raw: RawResourceResult =
            serde_json::from_value(output).map_err(|_| ResourceError::invalid_output())?;
        let uri = ResourceUri::parse(raw.uri).map_err(|_| ResourceError::invalid_output())?;
        if &uri != requested_uri {
            return Err(ResourceError::invalid_output());
        }
        let mime_type =
            MimeType::new(raw.mime_type).map_err(|_| ResourceError::invalid_output())?;
        if declaration
            .metadata()
            .mime_type()
            .is_some_and(|advertised| advertised != &mime_type)
        {
            return Err(ResourceError::invalid_output());
        }
        let limits = declaration.limits();
        let content = decode_content(raw.content, &mime_type, limits)?;
        let checksum =
            Sha256Digest::new(raw.checksum).map_err(|_| ResourceError::invalid_output())?;
        if checksum != digest_bytes(content.bytes()) {
            return Err(ResourceError::invalid_output());
        }
        let range = validate_range(raw.range, requested_range, &content)?;
        let provenance = validate_provenance(raw.provenance, declaration)?;
        let cache = validate_cache(raw.cache, limits)?;
        let hierarchy = raw
            .hierarchy
            .map(|raw_hierarchy| {
                self.validate_hierarchy(
                    raw_hierarchy,
                    target,
                    requested_uri,
                    declaration,
                    expected_tenant,
                )
            })
            .transpose()?;
        if let ResourceOperation::ListChildren { limit, .. } = operation
            && hierarchy
                .as_ref()
                .is_some_and(|value| value.children().len() > usize::from(*limit))
        {
            return Err(ResourceError::invalid_output());
        }
        if matches!(operation, ResourceOperation::ListChildren { .. }) && hierarchy.is_none() {
            return Err(ResourceError::invalid_output());
        }
        let object_reference = raw
            .object_reference
            .map(validate_object_reference)
            .transpose()?;
        Ok(ResourceResult::new(
            uri,
            mime_type,
            content,
            provenance,
            cache,
            range,
            hierarchy,
            checksum,
            object_reference,
        ))
    }

    fn validate_hierarchy(
        &self,
        raw: RawHierarchy,
        target: &PublicResourceName,
        requested_uri: &ResourceUri,
        declaration: &ResolvedDeclaration<'_>,
        expected_tenant: Option<&str>,
    ) -> Result<ResourceHierarchy, ResourceError> {
        if raw.child_uris.len() > MAX_HIERARCHY_CHILDREN {
            return Err(ResourceError::invalid_output());
        }
        let parent = raw
            .parent_uri
            .map(ResourceUri::parse)
            .transpose()
            .map_err(|_| ResourceError::invalid_output())?;
        let children = raw
            .child_uris
            .into_iter()
            .map(ResourceUri::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ResourceError::invalid_output())?;
        if parent.as_ref() == Some(requested_uri)
            || children.iter().any(|child| child == requested_uri)
        {
            return Err(ResourceError::invalid_output());
        }
        if children.iter().enumerate().any(|(index, child)| {
            children[index + 1..]
                .iter()
                .any(|candidate| candidate == child)
        }) {
            return Err(ResourceError::invalid_output());
        }
        for related_uri in parent.iter().chain(&children) {
            let Some(resolved) = self.catalog.resolve(target, related_uri) else {
                return Err(ResourceError::invalid_output());
            };
            if !related_uri.has_same_origin(requested_uri)
                || !tenant_binding_satisfied_value(
                    declaration.tenant_binding(),
                    related_uri,
                    &resolved.variables,
                    expected_tenant,
                )
            {
                return Err(ResourceError::invalid_output());
            }
        }
        let next_cursor = raw
            .next_cursor
            .map(OpaqueResourceValue::new)
            .transpose()
            .map_err(|_| ResourceError::invalid_output())?;
        Ok(ResourceHierarchy::new(parent, children, next_cursor))
    }
}

fn canonical_input(
    catalog_revision: &CatalogRevision,
    metadata: &ResourceMetadata,
    uri: &ResourceUri,
    variables: &BTreeMap<String, String>,
    request: &McpRequestContext,
    operation: &ResourceOperation,
    range: Option<ByteRange>,
) -> Value {
    let operation = match operation {
        ResourceOperation::Read => json!({"kind": "read"}),
        ResourceOperation::ListChildren { limit, cursor } => json!({
            "kind": "list_children", "limit": limit,
            "cursor": cursor.as_ref().map(OpaqueResourceValue::as_str),
        }),
    };
    let range =
        range.map(|range| json!({"start": range.start(), "end_inclusive": range.end_inclusive()}));
    let mut root = Map::new();
    root.insert(
        "protocol_revision".to_owned(),
        Value::String(request.metadata().protocol_revision().to_owned()),
    );
    root.insert(
        "catalog_revision".to_owned(),
        Value::String(catalog_revision.as_str().to_owned()),
    );
    root.insert(
        "public_name".to_owned(),
        Value::String(metadata.name().as_str().to_owned()),
    );
    root.insert(
        "schema_revision".to_owned(),
        Value::String(metadata.schema_revision().as_str().to_owned()),
    );
    root.insert(
        "required_extensions".to_owned(),
        exact_extension_values(metadata.required_extensions()),
    );
    root.insert(
        "negotiated_extensions".to_owned(),
        exact_extension_values(request.negotiated_extensions().extensions()),
    );
    root.insert("uri".to_owned(), Value::String(uri.as_str().to_owned()));
    root.insert(
        "variables".to_owned(),
        Value::Object(
            variables
                .iter()
                .map(|(name, value)| (name.clone(), Value::String(value.clone())))
                .collect(),
        ),
    );
    root.insert("operation".to_owned(), operation);
    if let Some(range) = range {
        root.insert("range".to_owned(), range);
    }
    Value::Object(root)
}

fn exact_extension_values(extensions: &BTreeSet<McpExtension>) -> Value {
    Value::Array(
        extensions
            .iter()
            .map(|extension| {
                json!({
                    "id": extension.id().as_str(),
                    "revision": extension.revision().as_str(),
                })
            })
            .collect(),
    )
}

fn extensions_satisfied(request: &McpRequestContext, required: &BTreeSet<McpExtension>) -> bool {
    required
        .iter()
        .all(|extension| request.negotiated_extensions().contains(extension))
}

fn capability_is_available(
    snapshot: &omnius_agent_capability_registry::AvailabilitySnapshot,
    capability: &omnius_agent_capability_registry::CapabilityKey,
) -> bool {
    let Ok(index) = snapshot
        .capabilities()
        .binary_search_by(|status| status.capability().cmp(capability))
    else {
        return false;
    };
    snapshot
        .capabilities()
        .get(index)
        .is_some_and(|status| status.compiled() && status.runtime().is_available())
}

fn exact_discovery_tenant_eligible(
    declaration: &ExactResourceDeclaration,
    context: &InvocationContext,
) -> bool {
    let tenant = context.tenant_id().map(|tenant| tenant.to_string());
    match declaration.tenant_binding() {
        TenantBinding::Global => true,
        TenantBinding::Authority => tenant.as_deref() == Some(declaration.uri().authority()),
        TenantBinding::PathVariable(_) => false,
    }
}

fn template_discovery_tenant_eligible(
    declaration: &ResourceTemplateDeclaration,
    context: &InvocationContext,
) -> bool {
    let tenant = context.tenant_id().map(|tenant| tenant.to_string());
    match declaration.tenant_binding() {
        TenantBinding::Global => true,
        TenantBinding::PathVariable(_) => tenant.is_some(),
        TenantBinding::Authority => {
            tenant.as_deref() == Some(declaration.uri_template().authority())
        }
    }
}

fn hide_ineligible_replacement(
    compatibility: &mut ResourceCompatibility,
    visible_names: &BTreeSet<String>,
) {
    let hidden_replacement_since = match compatibility {
        ResourceCompatibility::Deprecated {
            since,
            replacement: Some(replacement),
        } if !visible_names.contains(replacement.as_str()) => Some(since.clone()),
        ResourceCompatibility::Active
        | ResourceCompatibility::Deprecated {
            replacement: None, ..
        }
        | ResourceCompatibility::Deprecated {
            replacement: Some(_),
            ..
        } => None,
    };
    if let Some(since) = hidden_replacement_since {
        *compatibility = ResourceCompatibility::Deprecated {
            since,
            replacement: None,
        };
    }
}

fn tenant_binding_satisfied(
    binding: &TenantBinding,
    uri: &ResourceUri,
    variables: &BTreeMap<String, String>,
    context: &InvocationContext,
) -> bool {
    let tenant = context.tenant_id().map(|tenant| tenant.to_string());
    tenant_binding_satisfied_value(binding, uri, variables, tenant.as_deref())
}

fn tenant_binding_satisfied_value(
    binding: &TenantBinding,
    uri: &ResourceUri,
    variables: &BTreeMap<String, String>,
    expected_tenant: Option<&str>,
) -> bool {
    match binding {
        TenantBinding::Global => true,
        TenantBinding::Authority => expected_tenant.is_some_and(|tenant| uri.authority() == tenant),
        TenantBinding::PathVariable(variable) => expected_tenant.is_some_and(|tenant| {
            variables
                .get(variable.as_str())
                .is_some_and(|resolved| resolved == tenant)
        }),
    }
}

fn decode_content(
    raw: RawResourceContent,
    mime_type: &MimeType,
    limits: ResourceLimits,
) -> Result<ResourceContent, ResourceError> {
    let content = match raw {
        RawResourceContent::Text { text } => {
            if !mime_type.is_textual() || !mime_type.is_utf8_compatible() {
                return Err(ResourceError::invalid_output());
            }
            ResourceContent::Text(text)
        }
        RawResourceContent::Binary { base64 } => {
            let max_encoded = limits
                .max_content_bytes()
                .saturating_add(2)
                .saturating_div(3)
                .saturating_mul(4);
            if u64::try_from(base64.len()).unwrap_or(u64::MAX) > max_encoded {
                return Err(ResourceError::invalid_output());
            }
            let bytes = STANDARD
                .decode(base64.as_bytes())
                .map_err(|_| ResourceError::invalid_output())?;
            if STANDARD.encode(&bytes) != base64 {
                return Err(ResourceError::invalid_output());
            }
            ResourceContent::Binary(bytes)
        }
    };
    if u64::try_from(content.byte_len()).unwrap_or(u64::MAX) > limits.max_content_bytes() {
        return Err(ResourceError::invalid_output());
    }
    Ok(content)
}

fn validate_range(
    raw: Option<RawRangeResponse>,
    requested: Option<ByteRange>,
    content: &ResourceContent,
) -> Result<Option<ResourceRangeResponse>, ResourceError> {
    match (raw, requested) {
        (None, None) => Ok(None),
        (Some(raw), Some(requested)) => {
            let fulfilled = ByteRange::new(raw.start, raw.end_inclusive)
                .map_err(|_| ResourceError::invalid_output())?;
            if fulfilled != requested
                || raw.total_length <= raw.end_inclusive
                || u64::try_from(content.byte_len()).unwrap_or(u64::MAX) != fulfilled.length()
            {
                return Err(ResourceError::invalid_output());
            }
            Ok(Some(ResourceRangeResponse::new(
                fulfilled,
                raw.total_length,
            )))
        }
        _ => Err(ResourceError::invalid_output()),
    }
}

fn validate_provenance(
    raw: crate::result::RawProvenance,
    declaration: &ResolvedDeclaration<'_>,
) -> Result<ResourceProvenance, ResourceError> {
    if raw.capability_id != declaration.capability().id().as_str()
        || raw.capability_version != declaration.capability().version().as_str()
    {
        return Err(ResourceError::invalid_output());
    }
    let source_revision = OpaqueResourceValue::new(raw.source_revision)
        .map_err(|_| ResourceError::invalid_output())?;
    Ok(ResourceProvenance::new(
        declaration.capability().clone(),
        source_revision,
    ))
}

fn validate_cache(
    raw: crate::result::RawCacheMetadata,
    limits: ResourceLimits,
) -> Result<ResourceCacheMetadata, ResourceError> {
    let control = match raw.scope {
        RawCacheScope::Private => CacheControl::private(raw.max_age_seconds),
        RawCacheScope::Public => CacheControl::public(raw.max_age_seconds),
        RawCacheScope::NoStore if raw.max_age_seconds == 0 => Ok(CacheControl::no_store()),
        RawCacheScope::NoStore => Err(ResourceError::invalid_value()),
    }
    .map_err(|_| ResourceError::invalid_output())?;
    let declared = limits.cache_control();
    let scope_allowed = match declared.scope() {
        CacheScope::Public => true,
        CacheScope::Private => control.scope() != CacheScope::Public,
        CacheScope::NoStore => control.scope() == CacheScope::NoStore,
    };
    let lifetime_allowed = control.scope() == CacheScope::NoStore
        || control.max_age_seconds() <= declared.max_age_seconds();
    if !scope_allowed || !lifetime_allowed {
        return Err(ResourceError::invalid_output());
    }
    let etag = Sha256Digest::new(raw.etag).map_err(|_| ResourceError::invalid_output())?;
    Ok(ResourceCacheMetadata::new(etag, control))
}

fn validate_object_reference(
    raw: RawObjectReference,
) -> Result<ResourceObjectReference, ResourceError> {
    let store = OpaqueResourceValue::new(raw.store).map_err(|_| ResourceError::invalid_output())?;
    let object_id =
        OpaqueResourceValue::new(raw.object_id).map_err(|_| ResourceError::invalid_output())?;
    let version = raw
        .version
        .map(OpaqueResourceValue::new)
        .transpose()
        .map_err(|_| ResourceError::invalid_output())?;
    Ok(ResourceObjectReference::new(store, object_id, version))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        hex.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    Sha256Digest::from_hex(&hex)
}
