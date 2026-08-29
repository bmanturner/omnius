use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};

use crate::{CatalogError, ModuleCatalog};

/// The service-kit release represented by the base profile catalog.
pub const KIT_VERSION: &str = "0.1.0";
const PROFILE_SCHEMA_VERSION: u32 = 1;
const BASE_PROFILE_COUNT: usize = 10;
const BASE_PROFILE_SOURCE: &str = include_str!("../../../specs/machine/profiles.yaml");
const WEB_PROFILE_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/web-application-suite/profiles.yaml");

/// A typed entry in the authoritative base profile catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDefinition {
    /// Stable profile identifier.
    pub id: String,
    /// Human-readable purpose.
    pub description: String,
    /// Parent profile whose modules are inherited first.
    pub extends: Option<String>,
    /// Modules declared directly by this profile, in catalog order.
    pub modules: Vec<String>,
}

/// One selected provider for a mutually exclusive module capability.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProviderSelection {
    /// Stable provider capability slot.
    pub slot: String,
    /// Selected module occupying the slot.
    pub module: String,
}

/// Strict authoritative base profile catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileCatalog {
    bundle_version: String,
    profiles: Vec<ProfileDefinition>,
}

/// A profile with inheritance flattened and catalog constraints checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProfile {
    definition: ProfileDefinition,
    modules: Vec<String>,
    providers: Vec<ProviderSelection>,
    external_services: Vec<String>,
}

impl ResolvedProfile {
    /// Returns the selected profile definition.
    #[must_use]
    pub const fn definition(&self) -> &ProfileDefinition {
        &self.definition
    }

    /// Returns inherited modules followed by directly declared modules.
    #[must_use]
    pub fn modules(&self) -> &[String] {
        &self.modules
    }

    /// Returns provider slots in resolved module order.
    #[must_use]
    pub fn providers(&self) -> &[ProviderSelection] {
        &self.providers
    }

    /// Returns declared external services in first-module, first-declaration order.
    #[must_use]
    pub fn external_services(&self) -> &[String] {
        &self.external_services
    }
}

/// Failure to load or resolve the authoritative base profile catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileError {
    /// A supplied identifier was not canonical lowercase kebab case.
    InvalidName,
    /// No catalog entry has the supplied canonical identifier.
    UnknownProfile(String),
    /// The strict YAML catalog could not be decoded.
    Decode(String),
    /// Catalog versions or contents are incompatible.
    InvalidCatalog(String),
    /// The module catalog rejected the resolved selection.
    Modules(String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => formatter.write_str(
                "profile name must use lowercase ASCII letters, digits, and internal hyphens",
            ),
            Self::UnknownProfile(profile) => write!(formatter, "unknown base profile: {profile}"),
            Self::Decode(message) | Self::InvalidCatalog(message) | Self::Modules(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for ProfileError {}

impl From<CatalogError> for ProfileError {
    fn from(error: CatalogError) -> Self {
        Self::Modules(error.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseProfiles {
    schema_version: u32,
    bundle_version: String,
    profiles: Vec<RawProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileCatalogExtension {
    schema_version: String,
    extension_version: String,
    base_bundle_version: String,
    profiles: Vec<RawProfile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    id: String,
    description: String,
    extends: Option<String>,
    modules: Vec<String>,
}

impl ProfileCatalog {
    /// Loads the base and web-extension profile catalogs bundled into the generator.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] for schema drift, version mismatch, invalid
    /// inheritance, or an incompatible module selection.
    pub fn bundled() -> Result<Self, ProfileError> {
        let modules = bundled_modules()?;
        let mut catalog = Self::from_yaml(BASE_PROFILE_SOURCE, modules)?;
        let mut extension: ProfileCatalogExtension = serde_yaml::from_str(WEB_PROFILE_SOURCE)
            .map_err(|error| {
                ProfileError::Decode(format!("invalid web profile catalog extension: {error}"))
            })?;
        if extension.schema_version != "1.0.0" {
            return Err(ProfileError::InvalidCatalog(format!(
                "unsupported web profile schema {}; expected 1.0.0",
                extension.schema_version
            )));
        }
        if extension.extension_version.is_empty() {
            return Err(ProfileError::InvalidCatalog(
                "web profile catalog extension_version is empty".to_owned(),
            ));
        }
        if extension.base_bundle_version != catalog.bundle_version {
            return Err(ProfileError::InvalidCatalog(format!(
                "web profile catalog requires base bundle {}; bundled base is {}",
                extension.base_bundle_version, catalog.bundle_version
            )));
        }
        extension
            .profiles
            .sort_by(|left, right| left.id.cmp(&right.id));
        catalog.profiles.extend(
            extension
                .profiles
                .into_iter()
                .map(|profile| ProfileDefinition {
                    id: profile.id,
                    description: profile.description,
                    extends: profile.extends,
                    modules: profile.modules,
                }),
        );
        catalog.validate(modules)?;
        Ok(catalog)
    }

    /// Strictly loads the authoritative base profile YAML source.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] without partial results for malformed or
    /// incompatible input.
    pub fn from_yaml(source: &str, modules: &ModuleCatalog) -> Result<Self, ProfileError> {
        Self::decode(source, modules, Some(BASE_PROFILE_COUNT))
    }

    /// Strictly loads a deterministic base-plus-extension profile overlay.
    ///
    /// The base parser retains its exact nine-profile invariant. This overlay
    /// parser accepts additional profiles while applying the same version,
    /// inheritance, dependency, conflict, and provider validation.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] without partial results for malformed or
    /// incompatible input.
    pub fn from_overlay_yaml(source: &str, modules: &ModuleCatalog) -> Result<Self, ProfileError> {
        Self::decode(source, modules, None)
    }

    fn decode(
        source: &str,
        modules: &ModuleCatalog,
        expected_count: Option<usize>,
    ) -> Result<Self, ProfileError> {
        let base: BaseProfiles = serde_yaml::from_str(source)
            .map_err(|error| ProfileError::Decode(format!("invalid profile catalog: {error}")))?;
        if base.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::InvalidCatalog(format!(
                "unsupported profile schema {}; expected {PROFILE_SCHEMA_VERSION}",
                base.schema_version
            )));
        }
        if base.bundle_version != KIT_VERSION || base.bundle_version != modules.bundle_version {
            return Err(ProfileError::InvalidCatalog(format!(
                "profile bundle {} does not match kit/module bundle {KIT_VERSION}/{}",
                base.bundle_version, modules.bundle_version
            )));
        }
        if let Some(expected_count) = expected_count
            && base.profiles.len() != expected_count
        {
            return Err(ProfileError::InvalidCatalog(format!(
                "base profile catalog must contain exactly {expected_count} profiles; found {}",
                base.profiles.len()
            )));
        }
        if expected_count.is_none() && base.profiles.len() < BASE_PROFILE_COUNT {
            return Err(ProfileError::InvalidCatalog(format!(
                "profile overlay must retain all {BASE_PROFILE_COUNT} base profiles; found {}",
                base.profiles.len()
            )));
        }
        let profiles = base
            .profiles
            .into_iter()
            .map(|profile| ProfileDefinition {
                id: profile.id,
                description: profile.description,
                extends: profile.extends,
                modules: profile.modules,
            })
            .collect();
        let catalog = Self {
            bundle_version: base.bundle_version,
            profiles,
        };
        catalog.validate(modules)?;
        Ok(catalog)
    }

    /// Returns the shared base bundle version.
    #[must_use]
    pub fn bundle_version(&self) -> &str {
        &self.bundle_version
    }

    /// Returns all nine declarations in authoritative order.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileDefinition] {
        &self.profiles
    }

    /// Resolves one profile against this catalog and the base module catalog.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] for an invalid name, missing profile, invalid
    /// inheritance, or incompatible resolved modules.
    pub fn resolve(
        &self,
        profile: &str,
        modules: &ModuleCatalog,
    ) -> Result<ResolvedProfile, ProfileError> {
        if !valid_name(profile) {
            return Err(ProfileError::InvalidName);
        }
        let definition = self
            .profiles
            .iter()
            .find(|definition| definition.id == profile)
            .ok_or_else(|| ProfileError::UnknownProfile(profile.to_owned()))?;
        let by_id = self
            .profiles
            .iter()
            .map(|definition| (definition.id.as_str(), definition))
            .collect::<BTreeMap<_, _>>();
        let mut resolved = Vec::new();
        flatten(
            definition,
            &by_id,
            &mut Vec::new(),
            &mut BTreeSet::new(),
            &mut resolved,
        )?;
        let selected = resolved.iter().cloned().collect::<BTreeSet<_>>();
        modules.validate_selection(&selected)?;

        let mut providers = Vec::new();
        let mut external_services = Vec::new();
        let mut external_seen = BTreeSet::new();
        for id in &resolved {
            let module = modules.module(id).ok_or_else(|| {
                ProfileError::InvalidCatalog(format!(
                    "profile `{profile}` references unknown module `{id}`"
                ))
            })?;
            if let Some(slot) = &module.provider_slot {
                providers.push(ProviderSelection {
                    slot: slot.clone(),
                    module: id.clone(),
                });
            }
            for service in &module.external_services {
                if external_seen.insert(service.as_str()) {
                    external_services.push(service.clone());
                }
            }
        }
        Ok(ResolvedProfile {
            definition: definition.clone(),
            modules: resolved,
            providers,
            external_services,
        })
    }

    fn validate(&self, modules: &ModuleCatalog) -> Result<(), ProfileError> {
        let mut ids = BTreeSet::new();
        for profile in &self.profiles {
            validate_profile_shape(profile)?;
            if !ids.insert(profile.id.as_str()) {
                return Err(ProfileError::InvalidCatalog(format!(
                    "duplicate profile id `{}`",
                    profile.id
                )));
            }
        }
        for profile in &self.profiles {
            self.resolve(&profile.id, modules)?;
        }
        Ok(())
    }
}

/// Returns the process-wide validated base profile catalog.
///
/// # Errors
///
/// Returns the deterministic bundled-catalog error when checked-in sources drift.
pub fn bundled_profile_catalog() -> Result<&'static ProfileCatalog, ProfileError> {
    static CATALOG: LazyLock<Result<ProfileCatalog, ProfileError>> =
        LazyLock::new(ProfileCatalog::bundled);
    CATALOG.as_ref().map_err(Clone::clone)
}

/// Resolves one canonical profile from the authoritative base catalog.
///
/// # Errors
///
/// Returns [`ProfileError`] for invalid syntax or catalog integrity failures.
pub fn resolve_profile(profile: &str) -> Result<ResolvedProfile, ProfileError> {
    bundled_profile_catalog()?.resolve(profile, bundled_modules()?)
}

fn bundled_modules() -> Result<&'static ModuleCatalog, ProfileError> {
    static MODULES: LazyLock<Result<ModuleCatalog, CatalogError>> =
        LazyLock::new(ModuleCatalog::bundled);
    MODULES
        .as_ref()
        .map_err(|error| ProfileError::from(error.clone()))
}

fn validate_profile_shape(profile: &ProfileDefinition) -> Result<(), ProfileError> {
    if !valid_name(&profile.id) {
        return Err(ProfileError::InvalidCatalog(format!(
            "invalid profile id `{}`",
            profile.id
        )));
    }
    if profile.description.trim().is_empty() {
        return Err(ProfileError::InvalidCatalog(format!(
            "profile `{}` has an empty description",
            profile.id
        )));
    }
    if profile.modules.is_empty() {
        return Err(ProfileError::InvalidCatalog(format!(
            "profile `{}` declares no modules",
            profile.id
        )));
    }
    let mut direct = BTreeSet::new();
    for module in &profile.modules {
        if !valid_name(module) {
            return Err(ProfileError::InvalidCatalog(format!(
                "profile `{}` contains invalid module id `{module}`",
                profile.id
            )));
        }
        if !direct.insert(module.as_str()) {
            return Err(ProfileError::InvalidCatalog(format!(
                "profile `{}` repeats direct module `{module}`",
                profile.id
            )));
        }
    }
    Ok(())
}

fn flatten(
    profile: &ProfileDefinition,
    profiles: &BTreeMap<&str, &ProfileDefinition>,
    inheritance: &mut Vec<String>,
    installed: &mut BTreeSet<String>,
    modules: &mut Vec<String>,
) -> Result<(), ProfileError> {
    if inheritance.iter().any(|id| id == &profile.id) {
        inheritance.push(profile.id.clone());
        return Err(ProfileError::InvalidCatalog(format!(
            "profile inheritance cycle: {}",
            inheritance.join(" -> ")
        )));
    }
    inheritance.push(profile.id.clone());
    if let Some(parent) = profile.extends.as_deref() {
        let definition = profiles.get(parent).ok_or_else(|| {
            ProfileError::InvalidCatalog(format!(
                "profile `{}` extends unknown profile `{parent}`",
                profile.id
            ))
        })?;
        flatten(definition, profiles, inheritance, installed, modules)?;
    }
    for module in &profile.modules {
        if !installed.insert(module.clone()) {
            return Err(ProfileError::InvalidCatalog(format!(
                "profile `{}` repeats inherited module `{module}`",
                profile.id
            )));
        }
        modules.push(module.clone());
    }
    inheritance.pop();
    Ok(())
}

fn valid_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}
