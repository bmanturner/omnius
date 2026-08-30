use std::{collections::BTreeMap, fmt};

use omnius_agent_capability_registry::{CapabilityKey, TenantMode};

use crate::{
    CacheControl, CacheScope, CatalogRevision, MAX_REQUIRED_EXTENSIONS, PublicResourceName,
    ResourceCompatibility, ResourceError, ResourceLimits, ResourceMetadata, ResourceUri,
    ResourceUriTemplate, TemplateVariableName,
};

const MAX_CATALOG_ENTRIES: usize = 1_024;

/// Explicit binding between a resolved resource URI and the canonical tenant context.
#[derive(Clone, Eq, PartialEq)]
pub enum TenantBinding {
    /// The declaration is explicitly global and performs no URI tenant comparison.
    Global,
    /// The URI authority must exactly equal the canonical invocation tenant UUID.
    Authority,
    /// One decoded whole-segment template variable must equal the canonical tenant UUID.
    PathVariable(TemplateVariableName),
}

#[derive(Clone, Eq, PartialEq)]
struct DeclarationCore {
    metadata: ResourceMetadata,
    capability: CapabilityKey,
    tenant_mode: TenantMode,
    tenant_binding: TenantBinding,
    limits: ResourceLimits,
}

impl DeclarationCore {
    fn new(
        metadata: ResourceMetadata,
        capability: CapabilityKey,
        tenant_mode: TenantMode,
        tenant_binding: TenantBinding,
        limits: ResourceLimits,
    ) -> Result<Self, ResourceError> {
        let binding_is_global = matches!(tenant_binding, TenantBinding::Global);
        if (tenant_mode == TenantMode::Global) != binding_is_global
            || (tenant_mode != TenantMode::Global
                && limits.cache_control().scope() == CacheScope::Public)
        {
            return Err(ResourceError::invalid_declaration());
        }
        Ok(Self {
            metadata,
            capability,
            tenant_mode,
            tenant_binding,
            limits,
        })
    }
}

/// An immutable declaration for one exact canonical resource URI.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactResourceDeclaration {
    core: DeclarationCore,
    uri: ResourceUri,
}

impl ExactResourceDeclaration {
    /// Creates one exact resource declaration tied to a canonical capability revision.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for a path-variable binding or inconsistent tenant/cache policy.
    pub fn new(
        metadata: ResourceMetadata,
        uri: ResourceUri,
        capability: CapabilityKey,
        tenant_mode: TenantMode,
        tenant_binding: TenantBinding,
        limits: ResourceLimits,
    ) -> Result<Self, ResourceError> {
        if matches!(tenant_binding, TenantBinding::PathVariable(_)) {
            return Err(ResourceError::invalid_declaration());
        }
        Ok(Self {
            core: DeclarationCore::new(metadata, capability, tenant_mode, tenant_binding, limits)?,
            uri,
        })
    }

    /// Returns the explicit stable public metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ResourceMetadata {
        &self.core.metadata
    }

    /// Returns the exact canonical URI.
    #[must_use]
    pub const fn uri(&self) -> &ResourceUri {
        &self.uri
    }

    /// Returns the canonical capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.core.capability
    }

    /// Returns the declared canonical tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.core.tenant_mode
    }

    /// Returns the explicit URI tenant-binding policy.
    #[must_use]
    pub const fn tenant_binding(&self) -> &TenantBinding {
        &self.core.tenant_binding
    }

    /// Returns fixed decoded-content, range, and cache bounds.
    #[must_use]
    pub const fn limits(&self) -> ResourceLimits {
        self.core.limits
    }
}

/// An immutable declaration for one strict whole-segment resource URI template.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceTemplateDeclaration {
    core: DeclarationCore,
    uri_template: ResourceUriTemplate,
}

impl ResourceTemplateDeclaration {
    /// Creates one resource-template declaration tied to a canonical capability revision.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an undeclared tenant variable or inconsistent tenant/cache policy.
    pub fn new(
        metadata: ResourceMetadata,
        uri_template: ResourceUriTemplate,
        capability: CapabilityKey,
        tenant_mode: TenantMode,
        tenant_binding: TenantBinding,
        limits: ResourceLimits,
    ) -> Result<Self, ResourceError> {
        if let TenantBinding::PathVariable(variable) = &tenant_binding
            && !uri_template.has_variable(variable)
        {
            return Err(ResourceError::invalid_declaration());
        }
        Ok(Self {
            core: DeclarationCore::new(metadata, capability, tenant_mode, tenant_binding, limits)?,
            uri_template,
        })
    }

    /// Returns the explicit stable public metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ResourceMetadata {
        &self.core.metadata
    }

    /// Returns the strict canonical URI template.
    #[must_use]
    pub const fn uri_template(&self) -> &ResourceUriTemplate {
        &self.uri_template
    }

    /// Returns the canonical capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.core.capability
    }

    /// Returns the declared canonical tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.core.tenant_mode
    }

    /// Returns the explicit URI tenant-binding policy.
    #[must_use]
    pub const fn tenant_binding(&self) -> &TenantBinding {
        &self.core.tenant_binding
    }

    /// Returns fixed decoded-content, range, and cache bounds.
    #[must_use]
    pub const fn limits(&self) -> ResourceLimits {
        self.core.limits
    }
}

/// An immutable duplicate-free deterministic catalog of exact resources and templates.
pub struct ResourceCatalog {
    revision: CatalogRevision,
    list_cache_control: CacheControl,
    exact: BTreeMap<PublicResourceName, ExactResourceDeclaration>,
    templates: BTreeMap<PublicResourceName, ResourceTemplateDeclaration>,
    exact_uris: BTreeMap<ResourceUri, PublicResourceName>,
}

impl ResourceCatalog {
    /// Builds an immutable catalog and rejects duplicate or overlapping registrations.
    ///
    /// Authorized catalog metadata is visibility-sensitive, so only private caching is accepted.
    /// Exact URI/template overlap is rejected rather than resolved by registration order.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for duplicates, ambiguous templates, exact/template overlap,
    /// invalid replacements, excessive size, or unsafe catalog caching.
    pub fn new(
        revision: CatalogRevision,
        list_cache_control: CacheControl,
        exact_declarations: Vec<ExactResourceDeclaration>,
        template_declarations: Vec<ResourceTemplateDeclaration>,
    ) -> Result<Self, ResourceError> {
        let too_many_entries = exact_declarations
            .len()
            .checked_add(template_declarations.len())
            .is_none_or(|count| count > MAX_CATALOG_ENTRIES);
        let excessive_extension_requirements = exact_declarations
            .iter()
            .map(ExactResourceDeclaration::metadata)
            .chain(
                template_declarations
                    .iter()
                    .map(ResourceTemplateDeclaration::metadata),
            )
            .any(|metadata| metadata.required_extensions().len() > MAX_REQUIRED_EXTENSIONS);
        if list_cache_control.scope() != CacheScope::Private
            || too_many_entries
            || excessive_extension_requirements
        {
            return Err(ResourceError::invalid_declaration());
        }

        let mut exact = BTreeMap::new();
        let mut exact_uris = BTreeMap::new();
        for declaration in exact_declarations {
            let name = declaration.metadata().name().clone();
            if exact.contains_key(&name)
                || exact_uris
                    .insert(declaration.uri().clone(), name.clone())
                    .is_some()
            {
                return Err(ResourceError::invalid_declaration());
            }
            exact.insert(name, declaration);
        }

        let mut templates = BTreeMap::new();
        for declaration in template_declarations {
            let name = declaration.metadata().name().clone();
            if exact.contains_key(&name) || templates.insert(name, declaration).is_some() {
                return Err(ResourceError::invalid_declaration());
            }
        }

        for (index, left) in templates.values().enumerate() {
            if templates
                .values()
                .skip(index + 1)
                .any(|right| left.uri_template().overlaps(right.uri_template()))
            {
                return Err(ResourceError::invalid_declaration());
            }
        }
        if exact.values().any(|exact_declaration| {
            templates.values().any(|template_declaration| {
                template_declaration
                    .uri_template()
                    .matches_uri(exact_declaration.uri())
            })
        }) {
            return Err(ResourceError::invalid_declaration());
        }

        for metadata in exact
            .values()
            .map(ExactResourceDeclaration::metadata)
            .chain(
                templates
                    .values()
                    .map(ResourceTemplateDeclaration::metadata),
            )
        {
            if let ResourceCompatibility::Deprecated {
                replacement: Some(replacement),
                ..
            } = metadata.compatibility()
            {
                let replacement_metadata = exact
                    .get(replacement)
                    .map(ExactResourceDeclaration::metadata)
                    .or_else(|| {
                        templates
                            .get(replacement)
                            .map(ResourceTemplateDeclaration::metadata)
                    });
                if replacement == metadata.name()
                    || !replacement_metadata.is_some_and(|replacement_metadata| {
                        matches!(
                            replacement_metadata.compatibility(),
                            ResourceCompatibility::Active
                        )
                    })
                {
                    return Err(ResourceError::invalid_declaration());
                }
            }
        }

        Ok(Self {
            revision,
            list_cache_control,
            exact,
            templates,
            exact_uris,
        })
    }

    /// Validates that another catalog is a compatible successor of this catalog.
    ///
    /// A public name keeps its exact or template kind and every declaration field other than
    /// compatibility metadata. Active entries may remain active or enter one documented
    /// deprecation window. Deprecated entries cannot be reactivated or change that window, but
    /// may be removed.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when an active entry is removed, an immutable declaration changes,
    /// or a compatibility transition is unsafe.
    pub fn validate_successor(&self, successor: &Self) -> Result<(), ResourceError> {
        for (name, current) in &self.exact {
            if let Some(next) = successor.exact.get(name) {
                if current.uri != next.uri
                    || !immutable_core_matches(&current.core, &next.core)
                    || !compatibility_transition_is_valid(
                        current.metadata().compatibility(),
                        next.metadata().compatibility(),
                    )
                {
                    return Err(ResourceError::invalid_declaration());
                }
            } else if successor.templates.contains_key(name)
                || !current.metadata().compatibility().is_deprecated()
            {
                return Err(ResourceError::invalid_declaration());
            }
        }

        for (name, current) in &self.templates {
            if let Some(next) = successor.templates.get(name) {
                if current.uri_template != next.uri_template
                    || !immutable_core_matches(&current.core, &next.core)
                    || !compatibility_transition_is_valid(
                        current.metadata().compatibility(),
                        next.metadata().compatibility(),
                    )
                {
                    return Err(ResourceError::invalid_declaration());
                }
            } else if successor.exact.contains_key(name)
                || !current.metadata().compatibility().is_deprecated()
            {
                return Err(ResourceError::invalid_declaration());
            }
        }

        Ok(())
    }

    /// Returns the immutable catalog revision.
    #[must_use]
    pub const fn revision(&self) -> &CatalogRevision {
        &self.revision
    }

    /// Returns the prevalidated private list cache policy.
    #[must_use]
    pub const fn list_cache_control(&self) -> CacheControl {
        self.list_cache_control
    }

    /// Iterates exact declarations in stable public-name order.
    #[must_use]
    pub fn exact_resources(
        &self,
    ) -> impl ExactSizeIterator<Item = &ExactResourceDeclaration> + DoubleEndedIterator {
        self.exact.values()
    }

    /// Iterates templates in stable public-name order.
    #[must_use]
    pub fn resource_templates(
        &self,
    ) -> impl ExactSizeIterator<Item = &ResourceTemplateDeclaration> + DoubleEndedIterator {
        self.templates.values()
    }

    /// Resolves one safe URI to its unique stable public target name.
    #[must_use]
    pub fn target_for_uri(&self, uri: &ResourceUri) -> Option<&PublicResourceName> {
        if let Some(name) = self.exact_uris.get(uri) {
            return Some(name);
        }
        self.templates.iter().find_map(|(name, declaration)| {
            declaration.uri_template().matches_uri(uri).then_some(name)
        })
    }

    pub(crate) fn resolve<'a>(
        &'a self,
        target: &PublicResourceName,
        uri: &ResourceUri,
    ) -> Option<ResolvedResource<'a>> {
        if let Some(declaration) = self.exact.get(target) {
            return (declaration.uri() == uri).then_some(ResolvedResource {
                declaration: ResolvedDeclaration::Exact(declaration),
                variables: BTreeMap::new(),
            });
        }
        let declaration = self.templates.get(target)?;
        let variables = declaration.uri_template().resolve(uri)?;
        Some(ResolvedResource {
            declaration: ResolvedDeclaration::Template(declaration),
            variables,
        })
    }
}

fn immutable_core_matches(current: &DeclarationCore, next: &DeclarationCore) -> bool {
    immutable_metadata_matches(&current.metadata, &next.metadata)
        && current.capability == next.capability
        && current.tenant_mode == next.tenant_mode
        && current.tenant_binding == next.tenant_binding
        && current.limits == next.limits
}

fn immutable_metadata_matches(current: &ResourceMetadata, next: &ResourceMetadata) -> bool {
    current.name() == next.name()
        && current.title() == next.title()
        && current.description() == next.description()
        && current.schema_revision() == next.schema_revision()
        && current.mime_type() == next.mime_type()
        && current.required_extensions() == next.required_extensions()
}

fn compatibility_transition_is_valid(
    current: &ResourceCompatibility,
    next: &ResourceCompatibility,
) -> bool {
    match current {
        ResourceCompatibility::Active => true,
        ResourceCompatibility::Deprecated { .. } => current == next,
    }
}

pub(crate) enum ResolvedDeclaration<'a> {
    Exact(&'a ExactResourceDeclaration),
    Template(&'a ResourceTemplateDeclaration),
}

impl fmt::Debug for ResourceCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceCatalog([immutable declarations])")
    }
}

impl ResolvedDeclaration<'_> {
    pub(crate) const fn metadata(&self) -> &ResourceMetadata {
        match self {
            Self::Exact(declaration) => declaration.metadata(),
            Self::Template(declaration) => declaration.metadata(),
        }
    }

    pub(crate) const fn capability(&self) -> &CapabilityKey {
        match self {
            Self::Exact(declaration) => declaration.capability(),
            Self::Template(declaration) => declaration.capability(),
        }
    }

    pub(crate) const fn tenant_mode(&self) -> TenantMode {
        match self {
            Self::Exact(declaration) => declaration.tenant_mode(),
            Self::Template(declaration) => declaration.tenant_mode(),
        }
    }

    pub(crate) const fn tenant_binding(&self) -> &TenantBinding {
        match self {
            Self::Exact(declaration) => declaration.tenant_binding(),
            Self::Template(declaration) => declaration.tenant_binding(),
        }
    }

    pub(crate) const fn limits(&self) -> ResourceLimits {
        match self {
            Self::Exact(declaration) => declaration.limits(),
            Self::Template(declaration) => declaration.limits(),
        }
    }
}

pub(crate) struct ResolvedResource<'a> {
    pub(crate) declaration: ResolvedDeclaration<'a>,
    pub(crate) variables: BTreeMap<String, String>,
}
