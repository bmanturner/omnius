use std::{collections::BTreeSet, error::Error, fmt, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::release::ReleaseIdentity;

/// The only project-state schema understood by this generator release.
pub const PROJECT_STATE_SCHEMA_VERSION: u32 = 2;
/// The managed-marker format understood by this generator release.
pub const MANAGED_MARKER_VERSION: u32 = 1;
/// Location of generator state relative to a managed project.
pub const PROJECT_STATE_PATH: &str = ".omnius/service.toml";

/// Strict, versioned state for one generated service.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectState {
    /// Serialization schema version.
    pub schema_version: u32,
    /// Canonical service name.
    pub service: String,
    /// Immutable framework release that last changed the project.
    pub framework: ReleaseIdentity,
    /// Base profile and explicit selection changes.
    pub profile: ProfileSelection,
    /// Complete selected module set and installed versions.
    pub modules: Vec<SelectedModule>,
    /// Exact provider-slot selections derived from the ordered modules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<SelectedProvider>,
    /// Compose volumes retained after their owning module is removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_compose_volumes: Vec<String>,
    /// File ownership declarations.
    pub ownership: Vec<OwnershipRecord>,
    /// Managed regions and their last approved contents.
    pub managed_regions: Vec<ManagedRegionRecord>,
}

/// Base profile plus explicit module selection changes.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelection {
    /// Canonical profile identifier.
    pub id: String,
    /// Profile catalog version.
    pub version: String,
    /// Modules explicitly added after profile generation.
    #[serde(default)]
    pub additions: Vec<String>,
    /// Profile modules explicitly removed after generation.
    #[serde(default)]
    pub removals: Vec<String>,
}

/// An installed catalog module and its selected version.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedModule {
    /// Stable catalog identifier.
    pub id: String,
    /// Installed module version.
    pub version: String,
}

/// One provider-slot selection derived from the installed module list.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedProvider {
    /// Stable mutually exclusive provider capability.
    pub slot: String,
    /// Selected module occupying the slot.
    pub module: String,
}

/// Ownership of one project-relative path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipRecord {
    /// Normalized project-relative path.
    pub path: String,
    /// Rules governing automatic changes to the path.
    pub kind: OwnershipKind,
    /// Approved whole-file SHA-256 for generator-controlled files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_sha256: Option<String>,
}

/// File ownership enforced by the manager.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnershipKind {
    /// May change only from an approved, matching kit baseline.
    KitOwned,
    /// May change only by deterministic regeneration.
    Derived,
    /// Must never be changed by the generator.
    ApplicationOwned,
    /// Shared Cargo dependency lock, validated semantically rather than byte-for-byte.
    DependencyLock,
}

/// State for one independently reconciled region.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRegionRecord {
    /// Stable region identifier, unique within the project.
    pub id: String,
    /// File containing the region.
    pub path: String,
    /// Marker grammar version.
    pub marker_version: u32,
    /// SHA-256 of the exact bytes between the marker lines.
    pub content_hash: String,
}

/// Invalid serialized project state.
#[derive(Debug)]
pub enum StateError {
    /// TOML could not be decoded using the strict schema.
    Decode(toml::de::Error),
    /// State could not be encoded.
    Encode(toml::ser::Error),
    /// A schema invariant was violated.
    Invalid(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "invalid {PROJECT_STATE_PATH}: {error}"),
            Self::Encode(error) => write!(formatter, "cannot serialize project state: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl ProjectState {
    /// Parses and validates strict project state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for unknown fields, unsupported versions, duplicate
    /// records, unsafe paths, or invalid hashes.
    pub fn parse(source: &str) -> Result<Self, StateError> {
        let state: Self = toml::from_str(source).map_err(StateError::Decode)?;
        state.validate()?;
        Ok(state)
    }

    /// Serializes state in a stable, human-readable TOML representation.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if state is invalid or serialization fails.
    pub fn to_toml(&self) -> Result<String, StateError> {
        self.validate()?;
        let mut encoded = toml::to_string_pretty(self).map_err(StateError::Encode)?;
        if !encoded.ends_with('\n') {
            encoded.push('\n');
        }
        Ok(encoded)
    }

    /// Validates all state invariants without filesystem access.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Invalid`] for the first deterministic violation.
    pub fn validate(&self) -> Result<(), StateError> {
        validate_state_header(self)?;
        validate_selected_modules_and_providers(self)?;
        validate_profile_delta_and_retained_volumes(self)?;
        validate_ownership_records(self)?;
        validate_managed_region_records(&self.managed_regions)
    }

    /// Returns the ownership declaration for a path.
    #[must_use]
    pub fn ownership_of(&self, path: &str) -> Option<OwnershipKind> {
        self.ownership
            .iter()
            .find(|record| record.path == path)
            .map(|record| record.kind)
    }

    /// Returns the state record for a managed region.
    #[must_use]
    pub fn managed_region(&self, path: &str, id: &str) -> Option<&ManagedRegionRecord> {
        self.managed_regions
            .iter()
            .find(|region| region.path == path && region.id == id)
    }
}

fn validate_state_header(state: &ProjectState) -> Result<(), StateError> {
    if state.schema_version != PROJECT_STATE_SCHEMA_VERSION {
        return Err(StateError::Invalid(format!(
            "unsupported project state schema version {}; expected {}",
            state.schema_version, PROJECT_STATE_SCHEMA_VERSION
        )));
    }
    validate_identifier(&state.service, "service")?;
    validate_identifier(&state.profile.id, "profile")?;
    validate_version(state.framework.version(), "framework.version")?;
    validate_version(&state.profile.version, "profile.version")?;
    if state.profile.version != state.framework.version() {
        return Err(StateError::Invalid(format!(
            "profile version `{}` does not match framework version `{}`",
            state.profile.version,
            state.framework.version()
        )));
    }
    Ok(())
}

fn validate_selected_modules_and_providers(state: &ProjectState) -> Result<(), StateError> {
    let mut module_ids = BTreeSet::new();
    for module in &state.modules {
        validate_identifier(&module.id, "module id")?;
        validate_version(&module.version, "module version")?;
        if !module_ids.insert(module.id.as_str()) {
            return Err(StateError::Invalid(format!(
                "duplicate selected module `{}`",
                module.id
            )));
        }
    }
    let mut provider_slots = BTreeSet::new();
    for provider in &state.providers {
        validate_identifier(&provider.slot, "provider slot")?;
        validate_identifier(&provider.module, "provider module")?;
        if !module_ids.contains(provider.module.as_str()) {
            return Err(StateError::Invalid(format!(
                "provider slot `{}` selects uninstalled module `{}`",
                provider.slot, provider.module
            )));
        }
        if !provider_slots.insert(provider.slot.as_str()) {
            return Err(StateError::Invalid(format!(
                "duplicate provider slot `{}`",
                provider.slot
            )));
        }
    }
    Ok(())
}

fn validate_profile_delta_and_retained_volumes(state: &ProjectState) -> Result<(), StateError> {
    let mut retained_volumes = BTreeSet::new();
    for volume in &state.retained_compose_volumes {
        validate_identifier(volume, "retained Compose volume")?;
        if !retained_volumes.insert(volume.as_str()) {
            return Err(StateError::Invalid(format!(
                "duplicate retained Compose volume `{volume}`"
            )));
        }
    }
    validate_unique_identifiers(&state.profile.additions, "profile addition")?;
    validate_unique_identifiers(&state.profile.removals, "profile removal")?;
    if let Some(id) = state
        .profile
        .additions
        .iter()
        .find(|id| state.profile.removals.contains(id))
    {
        return Err(StateError::Invalid(format!(
            "module `{id}` appears in both profile additions and removals"
        )));
    }
    Ok(())
}

fn validate_ownership_records(state: &ProjectState) -> Result<(), StateError> {
    let mut owned_paths = BTreeSet::new();
    for record in &state.ownership {
        validate_relative_path(&record.path)?;
        if record.path == PROJECT_STATE_PATH {
            return Err(StateError::Invalid(format!(
                "project state `{PROJECT_STATE_PATH}` must not own itself"
            )));
        }
        match (record.kind, record.approved_sha256.as_deref()) {
            (OwnershipKind::KitOwned | OwnershipKind::Derived, Some(hash))
                if valid_sha256(hash) => {}
            (OwnershipKind::KitOwned | OwnershipKind::Derived, Some(_)) => {
                return Err(StateError::Invalid(format!(
                    "ownership record for `{}` has an invalid approved SHA-256",
                    record.path
                )));
            }
            (OwnershipKind::KitOwned | OwnershipKind::Derived, None) => {
                return Err(StateError::Invalid(format!(
                    "ownership record for `{}` requires an approved SHA-256",
                    record.path
                )));
            }
            (OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock, Some(_)) => {
                return Err(StateError::Invalid(format!(
                    "ownership record for `{}` must not have an approved SHA-256",
                    record.path
                )));
            }
            (OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock, None) => {}
        }
        if record.kind == OwnershipKind::DependencyLock && record.path != "Cargo.lock" {
            return Err(StateError::Invalid(format!(
                "`Cargo.lock` is the only path that may use `dependency-lock` ownership, found `{}`",
                record.path
            )));
        }
        if !owned_paths.insert(record.path.as_str()) {
            return Err(StateError::Invalid(format!(
                "duplicate ownership record for `{}`",
                record.path
            )));
        }
    }
    if state.ownership_of("Cargo.lock") != Some(OwnershipKind::DependencyLock) {
        return Err(StateError::Invalid(
            "schema-2 state must own `Cargo.lock` as `dependency-lock`".to_owned(),
        ));
    }
    Ok(())
}

fn validate_managed_region_records(
    managed_regions: &[ManagedRegionRecord],
) -> Result<(), StateError> {
    let mut region_ids = BTreeSet::new();
    let mut region_locations = BTreeSet::new();
    for region in managed_regions {
        validate_identifier(&region.id, "managed region id")?;
        validate_relative_path(&region.path)?;
        if region.marker_version != MANAGED_MARKER_VERSION {
            return Err(StateError::Invalid(format!(
                "managed region `{}` uses unsupported marker version {}",
                region.id, region.marker_version
            )));
        }
        if !valid_sha256(&region.content_hash) {
            return Err(StateError::Invalid(format!(
                "managed region `{}` has an invalid content hash",
                region.id
            )));
        }
        if !region_ids.insert(region.id.as_str()) {
            return Err(StateError::Invalid(format!(
                "duplicate managed region id `{}`",
                region.id
            )));
        }
        if !region_locations.insert((region.path.as_str(), region.id.as_str())) {
            return Err(StateError::Invalid(format!(
                "duplicate managed region `{}` in `{}`",
                region.id, region.path
            )));
        }
    }
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn validate_relative_path(path: &str) -> Result<(), StateError> {
    let parsed = Path::new(path);
    if path.is_empty()
        || path.contains('\\')
        || parsed.is_absolute()
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(StateError::Invalid(format!(
            "unsafe project-relative path `{path}`"
        )));
    }
    Ok(())
}

fn validate_unique_identifiers(values: &[String], label: &str) -> Result<(), StateError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(value, label)?;
        if !unique.insert(value.as_str()) {
            return Err(StateError::Invalid(format!("duplicate {label} `{value}`")));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), StateError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StateError::Invalid(format!("invalid {label} `{value}`")));
    }
    Ok(())
}

fn validate_version(value: &str, label: &str) -> Result<(), StateError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(StateError::Invalid(format!("invalid {label} `{value}`")));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
