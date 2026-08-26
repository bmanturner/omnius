use std::{collections::BTreeSet, error::Error, fmt};

use serde::Deserialize;

use crate::state::validate_relative_path;

const MODULE_CATALOG_SCHEMA_VERSION: u32 = 1;
const BUNDLED_CATALOG: &str = include_str!("../../../specs/machine/module-catalog.yaml");

/// Authoritative module catalog used by pure selection planning.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalog {
    /// Catalog serialization version.
    pub schema_version: u32,
    /// Version shared by module descriptors.
    pub bundle_version: String,
    /// Module descriptors in authoritative catalog order.
    pub modules: Vec<ModuleDefinition>,
}

/// Generator-relevant module descriptor plus validated catalog metadata.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleDefinition {
    /// Stable module identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Module version.
    pub version: String,
    /// Owning kit component.
    pub owner: String,
    /// Normative specification identifier.
    pub spec: String,
    /// Module kind.
    pub kind: String,
    /// Direct module prerequisites.
    pub requires: Vec<String>,
    /// Explicitly incompatible module identifiers.
    pub conflicts_with: Vec<String>,
    /// Mutually exclusive provider capability.
    pub provider_slot: Option<String>,
    /// Runtime criticality classification.
    pub criticality: String,
    /// Whether runtime configuration may disable the compiled module.
    pub runtime_toggle: bool,
    /// Required external services.
    pub external_services: Vec<String>,
    /// Primary upstream crates.
    pub primary_crates: Vec<String>,
    /// Acceptance criterion identifiers.
    pub acceptance: Vec<String>,
    /// Durable resources that removal must preserve.
    pub persistence: Vec<String>,
    /// Configuration contract.
    pub configuration: ModuleConfiguration,
    /// Registered HTTP routes.
    pub routes: Vec<String>,
    /// Registered background tasks.
    pub background_tasks: Vec<String>,
    /// Registered health checks.
    pub health_checks: Vec<String>,
    /// Metrics prefix.
    pub metrics_prefix: String,
    /// Test fixtures.
    pub test_fixtures: Vec<String>,
    /// Generator-owned outputs.
    pub generator_ownership: GeneratorOwnership,
    /// Human-readable safe removal behavior.
    pub removal_behavior: String,
}

/// Configuration metadata retained from the catalog.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfiguration {
    /// Configuration namespace.
    pub prefix: String,
    /// Optional schema path.
    pub schema: Option<String>,
    /// Secret-bearing configuration fields.
    pub secret_fields: Vec<String>,
}

/// Paths and regions the catalog permits the generator to change.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorOwnership {
    /// Files replaceable only from a matching kit baseline.
    pub kit_owned: Vec<String>,
    /// `path#region-id` managed region references.
    pub managed_regions: Vec<String>,
    /// Files regenerated entirely from selected modules.
    pub derived: Vec<String>,
}

/// Deterministic module selection or catalog validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogError {
    message: String,
}

impl CatalogError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CatalogError {}

impl ModuleCatalog {
    /// Loads the base module catalog bundled into the generator binary.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if the checked-in catalog is not strict and
    /// internally consistent.
    pub fn bundled() -> Result<Self, CatalogError> {
        Self::from_yaml(BUNDLED_CATALOG)
    }

    /// Decodes and validates a strict base module catalog.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for YAML, schema, dependency, ownership, or
    /// uniqueness violations.
    pub fn from_yaml(source: &str) -> Result<Self, CatalogError> {
        validate_base_wire_shape(source)?;
        let catalog: Self = decode_catalog("base module catalog", source)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Validates catalog-wide constraints without filesystem access.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for the first deterministic violation.
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != MODULE_CATALOG_SCHEMA_VERSION {
            return Err(CatalogError::new(format!(
                "unsupported module catalog schema version {}; expected {}",
                self.schema_version, MODULE_CATALOG_SCHEMA_VERSION
            )));
        }
        if self.bundle_version.is_empty() {
            return Err(CatalogError::new("module catalog bundle_version is empty"));
        }
        let mut ids = BTreeSet::new();
        for module in &self.modules {
            validate_id(&module.id)?;
            if !ids.insert(module.id.as_str()) {
                return Err(CatalogError::new(format!(
                    "duplicate module id `{}`",
                    module.id
                )));
            }
            if module.version.is_empty() {
                return Err(CatalogError::new(format!(
                    "module `{}` has an empty version",
                    module.id
                )));
            }
            validate_unique_list(&module.requires, &module.id, "requires")?;
            validate_unique_list(&module.conflicts_with, &module.id, "conflicts_with")?;
            if module.requires.contains(&module.id) {
                return Err(CatalogError::new(format!(
                    "module `{}` requires itself",
                    module.id
                )));
            }
            if module.conflicts_with.contains(&module.id) {
                return Err(CatalogError::new(format!(
                    "module `{}` conflicts with itself",
                    module.id
                )));
            }
            if module.provider_slot.as_deref().is_some_and(str::is_empty) {
                return Err(CatalogError::new(format!(
                    "module `{}` has an empty provider slot",
                    module.id
                )));
            }
            validate_ownership(module)?;
        }
        for module in &self.modules {
            for required in &module.requires {
                if !ids.contains(required.as_str()) {
                    return Err(CatalogError::new(format!(
                        "module `{}` requires unknown module `{required}`",
                        module.id
                    )));
                }
            }
            for conflict in &module.conflicts_with {
                if !ids.contains(conflict.as_str()) {
                    return Err(CatalogError::new(format!(
                        "module `{}` conflicts with unknown module `{conflict}`",
                        module.id
                    )));
                }
            }
        }
        for module in &self.modules {
            let mut visiting = BTreeSet::new();
            self.collect_dependencies(&module.id, &mut visiting, &mut BTreeSet::new())?;
        }
        Ok(())
    }

    /// Returns one module descriptor by stable ID.
    #[must_use]
    pub fn module(&self, id: &str) -> Option<&ModuleDefinition> {
        self.modules.iter().find(|module| module.id == id)
    }

    /// Resolves a requested module and all transitive prerequisites, then checks
    /// explicit conflicts and provider-slot exclusivity for the full selection.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for an unknown module or incompatible selection.
    pub fn resolve_add(
        &self,
        selected: &BTreeSet<String>,
        requested: &str,
    ) -> Result<BTreeSet<String>, CatalogError> {
        if self.module(requested).is_none() {
            return Err(CatalogError::new(format!(
                "unknown module `{requested}`; select an id from the module catalog"
            )));
        }
        let mut resolved = selected.clone();
        self.collect_dependencies(requested, &mut BTreeSet::new(), &mut resolved)?;
        resolved.insert(requested.to_owned());
        self.validate_selection(&resolved)?;
        Ok(resolved)
    }

    /// Removes one selected module only when no remaining module depends on it.
    /// Repeating removal of an absent module is an idempotent no-op.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for an unknown module or reverse dependencies.
    pub fn resolve_remove(
        &self,
        selected: &BTreeSet<String>,
        requested: &str,
    ) -> Result<BTreeSet<String>, CatalogError> {
        if self.module(requested).is_none() {
            return Err(CatalogError::new(format!(
                "unknown module `{requested}`; select an id from the module catalog"
            )));
        }
        if !selected.contains(requested) {
            return Ok(selected.clone());
        }
        let mut blockers = Vec::new();
        for id in selected {
            if id != requested && self.depends_on(id, requested, &mut BTreeSet::new())? {
                blockers.push(id.as_str());
            }
        }
        if !blockers.is_empty() {
            return Err(CatalogError::new(format!(
                "cannot remove module `{requested}`; selected dependents: {}",
                blockers.join(", ")
            )));
        }
        let mut resolved = selected.clone();
        resolved.remove(requested);
        self.validate_selection(&resolved)?;
        Ok(resolved)
    }

    /// Checks dependency closure, conflicts, and provider slots for a selection.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] with an actionable deterministic diagnostic.
    pub fn validate_selection(&self, selected: &BTreeSet<String>) -> Result<(), CatalogError> {
        for id in selected {
            let module = self.module(id).ok_or_else(|| {
                CatalogError::new(format!("project state selects unknown module `{id}`"))
            })?;
            for required in &module.requires {
                if !selected.contains(required) {
                    return Err(CatalogError::new(format!(
                        "selected module `{id}` requires missing module `{required}`"
                    )));
                }
            }
        }

        let selected_ids: Vec<&str> = selected.iter().map(String::as_str).collect();
        for (index, left_id) in selected_ids.iter().enumerate() {
            let left = self
                .module(left_id)
                .ok_or_else(|| CatalogError::new(format!("unknown module `{left_id}`")))?;
            for right_id in &selected_ids[index + 1..] {
                let right = self
                    .module(right_id)
                    .ok_or_else(|| CatalogError::new(format!("unknown module `{right_id}`")))?;
                if left.conflicts_with.iter().any(|id| id == right.id.as_str())
                    || right.conflicts_with.iter().any(|id| id == left.id.as_str())
                {
                    return Err(CatalogError::new(format!(
                        "module conflict: `{}` cannot be selected with `{}`",
                        left.id, right.id
                    )));
                }
                if left.provider_slot.is_some() && left.provider_slot == right.provider_slot {
                    return Err(CatalogError::new(format!(
                        "provider slot `{}` has multiple selected providers: `{}` and `{}`",
                        left.provider_slot.as_deref().unwrap_or_default(),
                        left.id,
                        right.id
                    )));
                }
            }
        }
        Ok(())
    }

    fn collect_dependencies(
        &self,
        id: &str,
        visiting: &mut BTreeSet<String>,
        collected: &mut BTreeSet<String>,
    ) -> Result<(), CatalogError> {
        if collected.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(CatalogError::new(format!(
                "module dependency cycle contains `{id}`"
            )));
        }
        let module = self
            .module(id)
            .ok_or_else(|| CatalogError::new(format!("unknown module `{id}`")))?;
        for required in &module.requires {
            self.collect_dependencies(required, visiting, collected)?;
            collected.insert(required.clone());
        }
        visiting.remove(id);
        Ok(())
    }

    fn depends_on(
        &self,
        id: &str,
        target: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Result<bool, CatalogError> {
        if !visiting.insert(id.to_owned()) {
            return Err(CatalogError::new(format!(
                "module dependency cycle contains `{id}`"
            )));
        }
        let module = self
            .module(id)
            .ok_or_else(|| CatalogError::new(format!("unknown module `{id}`")))?;
        for required in &module.requires {
            if required == target || self.depends_on(required, target, visiting)? {
                visiting.remove(id);
                return Ok(true);
            }
        }
        visiting.remove(id);
        Ok(false)
    }
}

fn decode_catalog<T: for<'de> Deserialize<'de>>(
    label: &str,
    source: &str,
) -> Result<T, CatalogError> {
    serde_yaml::from_str(source)
        .map_err(|error| CatalogError::new(format!("invalid {label}: {error}")))
}

fn validate_base_wire_shape(source: &str) -> Result<(), CatalogError> {
    let value: serde_yaml::Value = decode_catalog("base module catalog", source)?;
    for module in wire_modules(&value, "base module catalog")? {
        if !module.contains_key(serde_yaml::Value::String("provider_slot".to_owned())) {
            return Err(CatalogError::new(
                "base module catalog entries must explicitly declare provider_slot",
            ));
        }
        validate_wire_managed_regions(module, true)?;
    }
    Ok(())
}

fn wire_modules<'a>(
    value: &'a serde_yaml::Value,
    label: &str,
) -> Result<Vec<&'a serde_yaml::Mapping>, CatalogError> {
    let root = value
        .as_mapping()
        .ok_or_else(|| CatalogError::new(format!("{label} root must be a mapping")))?;
    let modules = root
        .get(serde_yaml::Value::String("modules".to_owned()))
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| CatalogError::new(format!("{label} modules must be a sequence")))?;
    modules
        .iter()
        .map(|module| {
            module
                .as_mapping()
                .ok_or_else(|| CatalogError::new(format!("{label} module must be a mapping")))
        })
        .collect()
}

fn validate_wire_managed_regions(
    module: &serde_yaml::Mapping,
    require_path_reference: bool,
) -> Result<(), CatalogError> {
    let regions = module
        .get(serde_yaml::Value::String("generator_ownership".to_owned()))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|ownership| {
            ownership.get(serde_yaml::Value::String("managed_regions".to_owned()))
        })
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| CatalogError::new("module managed_regions must be a sequence"))?;
    for region in regions {
        let declaration = region
            .as_str()
            .ok_or_else(|| CatalogError::new("module managed region must be a string"))?;
        if declaration.trim().is_empty()
            || declaration.bytes().any(|byte| byte.is_ascii_control())
            || (require_path_reference && !declaration.contains('#'))
        {
            return Err(CatalogError::new(format!(
                "invalid managed region declaration `{declaration}`"
            )));
        }
    }
    Ok(())
}

fn validate_ownership(module: &ModuleDefinition) -> Result<(), CatalogError> {
    validate_unique_list(
        &module.generator_ownership.kit_owned,
        &module.id,
        "generator_ownership.kit_owned",
    )?;
    validate_unique_list(
        &module.generator_ownership.managed_regions,
        &module.id,
        "generator_ownership.managed_regions",
    )?;
    validate_unique_list(
        &module.generator_ownership.derived,
        &module.id,
        "generator_ownership.derived",
    )?;
    for path in module
        .generator_ownership
        .kit_owned
        .iter()
        .chain(&module.generator_ownership.derived)
    {
        validate_relative_path(path).map_err(|error| {
            CatalogError::new(format!("module `{}` ownership: {error}", module.id))
        })?;
    }
    for reference in &module.generator_ownership.managed_regions {
        let Some((path, id)) = reference.rsplit_once('#') else {
            if reference.trim().is_empty() || reference.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(CatalogError::new(format!(
                    "module `{}` has invalid operational ownership declaration `{reference}`",
                    module.id
                )));
            }
            continue;
        };
        let wildcard_components = path
            .split('/')
            .filter(|component| *component == "*")
            .count();
        if wildcard_components > 1
            || path
                .split('/')
                .any(|component| component.contains('*') && component != "*")
        {
            return Err(CatalogError::new(format!(
                "module `{}` has unsupported managed path pattern `{path}`",
                module.id
            )));
        }
        let wildcard_free = path.replace('*', "placeholder");
        validate_relative_path(&wildcard_free).map_err(|error| {
            CatalogError::new(format!("module `{}` ownership: {error}", module.id))
        })?;
        validate_id(id)?;
    }
    Ok(())
}

fn validate_unique_list(values: &[String], module: &str, field: &str) -> Result<(), CatalogError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value.as_str()) {
            return Err(CatalogError::new(format!(
                "module `{module}` has duplicate `{value}` in {field}"
            )));
        }
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), CatalogError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CatalogError::new(format!(
            "invalid module or region id `{value}`"
        )));
    }
    Ok(())
}
