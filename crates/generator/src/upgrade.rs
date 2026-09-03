use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path},
};

use serde::{Deserialize, de::IgnoredAny};

use crate::{
    KIT_VERSION,
    application_templates::application_template,
    manager::{
        MANAGER_DERIVED_PATHS, ManagementPlan, ManagerError, PlanOperation, ProjectSnapshot,
        doctor, finish_upgrade_plan, preserves_historical_path,
        render_derived_with_retained_volumes, render_region, retain_selected_compose_volumes,
    },
    modules::ModuleCatalog,
    region::{parse_managed_regions, reconcile_managed_region},
    release::ReleaseIdentity,
    render::render_embedded_base_files,
    resolve_profile,
    state::{
        MANAGED_MARKER_VERSION, ManagedRegionRecord, OwnershipKind, OwnershipRecord,
        PROJECT_STATE_PATH, ProfileSelection, ProjectState, SelectedModule, SelectedProvider,
        sha256_hex, validate_relative_path,
    },
};

const LEGACY_VERSION: &str = "0.0.0";
const PRIOR_VERSION: &str = "0.1.0";
const LAST_SCHEMA_1_VERSION: &str = "0.2.0";
const PROJECT_NAME_PLACEHOLDER: &str = "{{project-name}}";
const APPLICATION_MIGRATION_MIN: u64 = 9_000_000_000_000_000_000;
const APPLICATION_MIGRATION_MAX: u64 = 9_099_999_999_999_999_999;
const LEGACY_BASELINE_0_0: &str = include_str!("../tests/fixtures/prior-0.0.0/baseline.json");
const LEGACY_BASELINE_0_1: &str = include_str!("../tests/fixtures/prior-0.1.0/baseline.json");
const LEGACY_BASELINE_0_2: &str = include_str!("../tests/fixtures/prior-0.2.0/baseline.json");
#[cfg(test)]
pub(crate) const TEST_LEGACY_VERSION: &str = "0.2.0-test";
#[cfg(test)]
const TEST_LEGACY_SERVICE: &str = "legacy-fixture";
#[cfg(test)]
const TEST_LEGACY_STATE_NORMALIZED: &str = r#"schema_version = 1
kit_version = "0.2.0-test"
service = "{{project-name}}"
retained_compose_volumes = []
providers = []
managed_regions = []

[[modules]]
id = "core"
version = "0.1.0"

[[ownership]]
path = ".omnius/service.toml"
kind = "kit-owned"

[[ownership]]
path = "Cargo.toml"
kind = "kit-owned"

[[ownership]]
path = "apps/service/src/application.rs"
kind = "application-owned"

[[ownership]]
path = "crates/legacy/Cargo.toml"
kind = "kit-owned"

[[ownership]]
path = "crates/legacy/src/lib.rs"
kind = "kit-owned"

[[ownership]]
path = "migrations/9000000000000000000_fixture.sql"
kind = "application-owned"

[profile]
id = "minimal"
version = "0.2.0-test"
additions = []
removals = []
"#;
const TARGET_APPLICATION_PATHS: &[&str] = &[
    "Cargo.toml",
    "README.md",
    "apps/service/Cargo.toml",
    "apps/service/src/application.rs",
    "apps/service/src/composition.rs",
];

/// One supported, direct service-kit upgrade transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UpgradeRecipe {
    from: &'static str,
    to: &'static str,
}

/// Private versioned migration transitions compiled into this generator release.
const UPGRADE_RECIPES: &[UpgradeRecipe] = &[
    UpgradeRecipe {
        from: LEGACY_VERSION,
        to: KIT_VERSION,
    },
    UpgradeRecipe {
        from: PRIOR_VERSION,
        to: KIT_VERSION,
    },
    UpgradeRecipe {
        from: LAST_SCHEMA_1_VERSION,
        to: KIT_VERSION,
    },
];

#[derive(Clone, Copy)]
struct FrozenRecipe {
    public: UpgradeRecipe,
    profile_version: &'static str,
    module_version: &'static str,
    baseline: &'static str,
}
#[cfg(test)]
const TEST_FROZEN_RECIPE: FrozenRecipe = FrozenRecipe {
    public: UpgradeRecipe {
        from: TEST_LEGACY_VERSION,
        to: KIT_VERSION,
    },
    profile_version: TEST_LEGACY_VERSION,
    module_version: PRIOR_VERSION,
    baseline: "",
};

const FROZEN_RECIPES: &[FrozenRecipe] = &[
    FrozenRecipe {
        public: UPGRADE_RECIPES[0],
        profile_version: LEGACY_VERSION,
        module_version: LEGACY_VERSION,
        baseline: LEGACY_BASELINE_0_0,
    },
    FrozenRecipe {
        public: UPGRADE_RECIPES[1],
        profile_version: PRIOR_VERSION,
        module_version: PRIOR_VERSION,
        baseline: LEGACY_BASELINE_0_1,
    },
    FrozenRecipe {
        public: UPGRADE_RECIPES[2],
        profile_version: LAST_SCHEMA_1_VERSION,
        module_version: PRIOR_VERSION,
        baseline: LEGACY_BASELINE_0_2,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectState {
    schema_version: u32,
    kit_version: String,
    service: String,
    profile: LegacyProfileSelection,
    modules: Vec<LegacySelectedModule>,
    #[serde(default)]
    providers: Vec<LegacySelectedProvider>,
    #[serde(default)]
    retained_compose_volumes: Vec<String>,
    ownership: Vec<LegacyOwnershipRecord>,
    #[serde(default)]
    managed_regions: Vec<LegacyManagedRegionRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProfileSelection {
    id: String,
    version: String,
    #[serde(default)]
    additions: Vec<String>,
    #[serde(default)]
    removals: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySelectedModule {
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySelectedProvider {
    slot: String,
    module: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyOwnershipRecord {
    path: String,
    kind: LegacyOwnershipKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum LegacyOwnershipKind {
    KitOwned,
    Derived,
    ApplicationOwned,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct LegacyManagedRegionRecord {
    id: String,
    path: String,
    marker_version: u32,
    content_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenBaseline {
    schema_version: u32,
    captured_release: String,
    baseline_byte_paths: Vec<String>,
    content_blobs: BTreeMap<String, FrozenContentBlob>,
    files: Vec<FrozenFileRecord>,
    fixture_service: String,
    module_versions: BTreeMap<String, String>,
    #[serde(rename = "profile")]
    _profile: IgnoredAny,
    profiles: BTreeMap<String, FrozenProfile>,
    #[serde(default, rename = "recipe_authority")]
    _recipe_authority: Option<IgnoredAny>,
    #[serde(default, rename = "release_fixture_sources")]
    _release_fixture_sources: Option<IgnoredAny>,
    #[serde(default, rename = "catalog_artifact_records")]
    _catalog_artifact_records: Option<IgnoredAny>,
    #[serde(default, rename = "catalog_missing_declarations")]
    _catalog_missing_declarations: Option<IgnoredAny>,
    #[serde(default, rename = "catalog_sources")]
    _catalog_sources: Option<IgnoredAny>,
    #[serde(default, rename = "managed_regions")]
    _managed_regions: Option<IgnoredAny>,
    #[serde(default, rename = "modules")]
    _modules: Option<IgnoredAny>,
    #[serde(default, rename = "providers")]
    _providers: Option<IgnoredAny>,
    #[serde(default, rename = "source_inputs")]
    _source_inputs: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenContentBlob {
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenFileRecord {
    path: String,
    class: FrozenOwnershipClass,
    sha256: String,
    normalized_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum FrozenOwnershipClass {
    KitOwned,
    Derived,
    ApplicationOwned,
    DependencyLock,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenProfile {
    modules: Vec<String>,
    #[serde(rename = "providers")]
    _providers: IgnoredAny,
    runtime_disabled_modules: Vec<String>,
}

struct TargetProject {
    state: ProjectState,
    files: BTreeMap<String, String>,
    base_files: BTreeMap<String, String>,
}
#[cfg(test)]
pub(crate) fn test_legacy_files() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            PROJECT_STATE_PATH.to_owned(),
            TEST_LEGACY_STATE_NORMALIZED.replace(PROJECT_NAME_PLACEHOLDER, TEST_LEGACY_SERVICE),
        ),
        ("Cargo.lock".to_owned(), "version = 4\n".to_owned()),
        (
            "Cargo.toml".to_owned(),
            "[workspace]\nmembers = [\"apps/service\", \"crates/legacy\"]\nresolver = \"3\"\n"
                .to_owned(),
        ),
        (
            "apps/service/src/application.rs".to_owned(),
            "pub fn application_owned() -> &'static str { \"preserved\" }\n".to_owned(),
        ),
        (
            "crates/legacy/Cargo.toml".to_owned(),
            "[package]\nname = \"omnius-legacy\"\nversion = \"0.2.0\"\nedition = \"2024\"\n"
                .to_owned(),
        ),
        (
            "crates/legacy/src/lib.rs".to_owned(),
            "pub const LEGACY: bool = true;\n".to_owned(),
        ),
        (
            "migrations/9000000000000000000_fixture.sql".to_owned(),
            "CREATE TABLE application_fixture (id bigint PRIMARY KEY);\n".to_owned(),
        ),
    ])
}

#[cfg(test)]
fn test_frozen_baseline() -> FrozenBaseline {
    let files = test_legacy_files()
        .into_iter()
        .map(|(path, contents)| {
            let class = match path.as_str() {
                "Cargo.lock" => FrozenOwnershipClass::DependencyLock,
                "apps/service/src/application.rs"
                | "migrations/9000000000000000000_fixture.sql" => {
                    FrozenOwnershipClass::ApplicationOwned
                }
                _ => FrozenOwnershipClass::KitOwned,
            };
            let normalized = contents.replace(TEST_LEGACY_SERVICE, PROJECT_NAME_PLACEHOLDER);
            FrozenFileRecord {
                path,
                class,
                sha256: sha256_hex(contents.as_bytes()),
                normalized_sha256: sha256_hex(normalized.as_bytes()),
            }
        })
        .collect();
    let state_hash = sha256_hex(TEST_LEGACY_STATE_NORMALIZED.as_bytes());
    FrozenBaseline {
        schema_version: 1,
        captured_release: TEST_LEGACY_VERSION.to_owned(),
        baseline_byte_paths: vec![PROJECT_STATE_PATH.to_owned()],
        content_blobs: BTreeMap::from([(
            state_hash,
            FrozenContentBlob {
                text: TEST_LEGACY_STATE_NORMALIZED.to_owned(),
            },
        )]),
        files,
        fixture_service: TEST_LEGACY_SERVICE.to_owned(),
        module_versions: BTreeMap::from([("core".to_owned(), PRIOR_VERSION.to_owned())]),
        _profile: IgnoredAny,
        profiles: BTreeMap::from([(
            "minimal".to_owned(),
            FrozenProfile {
                modules: vec!["core".to_owned()],
                _providers: IgnoredAny,
                runtime_disabled_modules: Vec::new(),
            },
        )]),
        _recipe_authority: None,
        _release_fixture_sources: None,
        _catalog_artifact_records: None,
        _catalog_missing_declarations: None,
        _catalog_sources: None,
        _managed_regions: None,
        _modules: None,
        _providers: None,
        _source_inputs: None,
    }
}

/// Loads and validates a schema-1 project without widening the public state parser.
///
/// The returned snapshot contains exact legacy project inputs, but its `state` and
/// `base_files` describe the schema-2 target. The raw schema-1 state remains in
/// `snapshot.files` so pure planning can decode and validate it again.
pub(crate) fn load_legacy_snapshot(
    project_root: &Path,
    target_release: &ReleaseIdentity,
    catalog: &ModuleCatalog,
) -> Result<ProjectSnapshot, ManagerError> {
    validate_target(catalog, target_release, target_release.version())?;
    reject_symlink_root(project_root)?;
    let state_bytes = read_required_regular(project_root, PROJECT_STATE_PATH)?;
    let state_source = utf8_file(PROJECT_STATE_PATH, state_bytes)?;
    let legacy = decode_legacy_state(&state_source)?;
    let recipe = frozen_recipe(&legacy.kit_version, target_release.version())?;
    let baseline = parse_frozen_baseline(recipe)?;
    validate_legacy_state(&legacy, recipe, &baseline)?;

    let mut files = BTreeMap::new();
    let mut lockfile = None;
    for record in &baseline.files {
        let bytes = read_required_regular(project_root, &record.path)?;
        if record.path == "Cargo.lock" {
            if let Ok(contents) = String::from_utf8(bytes.clone()) {
                files.insert(record.path.clone(), contents);
            }
            lockfile = Some(bytes);
        } else {
            files.insert(record.path.clone(), utf8_file(&record.path, bytes)?);
        }
    }
    files.insert(PROJECT_STATE_PATH.to_owned(), state_source);
    read_extra_application_migrations(project_root, &baseline, &mut files)?;
    scan_legacy_forbidden_roots(project_root, &baseline)?;
    validate_source_file_map(&legacy, &baseline, &files, lockfile.as_deref())?;

    let provisional = ProjectSnapshot {
        state: target_state_skeleton(&legacy, target_release, catalog)?,
        files,
        release_identity: target_release.clone(),
        base_files: BTreeMap::new(),
        provenance_diagnostics: Vec::new(),
        lockfile,
    };
    let target = build_target_project(catalog, &provisional, &legacy, &baseline)?;
    let mut source_files = provisional.files.clone();
    read_existing_target_application_files(
        project_root,
        &target.state,
        &baseline,
        &mut source_files,
    )?;
    let actual_files = source_files.clone();
    let target = build_target_project_with_files(
        catalog,
        &provisional,
        &legacy,
        &baseline,
        &source_files,
        target.base_files,
    )?;

    Ok(ProjectSnapshot {
        state: target.state,
        files: actual_files,
        release_identity: target_release.clone(),
        base_files: target.base_files,
        provenance_diagnostics: Vec::new(),
        lockfile: provisional.lockfile,
    })
}

/// Produces a pure, deterministic upgrade plan from a supplied project snapshot.
///
/// Schema-1 state is decoded privately from the raw state file and never through
/// [`ProjectState::parse`]. Cargo resolution owns the later lockfile operation;
/// this plan contains ordinary file operations followed by exactly one state write.
///
/// # Errors
///
/// Returns [`ManagerError`] for unsupported releases, invalid schema-1 state,
/// frozen-baseline drift, unsafe ownership, or an invalid target selection.
pub(crate) fn plan_upgrade(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    target_version: &str,
) -> Result<ManagementPlan, ManagerError> {
    validate_target(catalog, &snapshot.release_identity, target_version)?;
    let source = snapshot.files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject(format!("missing required `{PROJECT_STATE_PATH}`"))
    })?;

    if let Ok(current) = ProjectState::parse(source) {
        if current != snapshot.state {
            return Err(ManagerError::InvalidProject(
                "schema-2 snapshot state does not match the raw project state".to_owned(),
            ));
        }
        if current.framework == snapshot.release_identity {
            let report = doctor(catalog, snapshot);
            if !report.healthy {
                return Err(ManagerError::Preflight(report.diagnostics));
            }
            return finish_upgrade_plan(target_version, Vec::new(), Vec::new());
        }
        return Err(ManagerError::InvalidProject(format!(
            "unsupported schema-2 service-kit update {} -> {target_version}",
            current.framework.version()
        )));
    }

    let legacy = decode_legacy_state(source)?;
    let recipe = frozen_recipe(&legacy.kit_version, target_version)?;
    let baseline = parse_frozen_baseline(recipe)?;
    validate_legacy_state(&legacy, recipe, &baseline)?;
    validate_source_file_map(
        &legacy,
        &baseline,
        &snapshot.files,
        snapshot.lockfile.as_deref(),
    )?;
    let target = build_target_project(catalog, snapshot, &legacy, &baseline)?;
    let operations = build_upgrade_operations(snapshot, &legacy, &baseline, &target)?;
    let preserved = preserved_paths(catalog, &target.state);
    let plan = finish_upgrade_plan(target_version, operations, preserved)?;
    validate_pure_legacy_plan(&plan)?;
    Ok(plan)
}

fn validate_target(
    catalog: &ModuleCatalog,
    release_identity: &ReleaseIdentity,
    target: &str,
) -> Result<(), ManagerError> {
    catalog.validate()?;
    if target != KIT_VERSION || target != catalog.bundle_version {
        return Err(ManagerError::InvalidProject(format!(
            "unsupported service-kit upgrade target `{target}`; this generator supports `{KIT_VERSION}`"
        )));
    }
    if target != release_identity.version() {
        return Err(ManagerError::InvalidProject(format!(
            "service-kit upgrade target `{target}` does not match framework release `{}`",
            release_identity.version()
        )));
    }
    Ok(())
}

fn frozen_recipe(from: &str, to: &str) -> Result<&'static FrozenRecipe, ManagerError> {
    #[cfg(test)]
    if from == TEST_LEGACY_VERSION && to == KIT_VERSION {
        return Ok(&TEST_FROZEN_RECIPE);
    }
    FROZEN_RECIPES
        .iter()
        .find(|recipe| recipe.public.from == from && recipe.public.to == to)
        .ok_or_else(|| {
            ManagerError::InvalidProject(format!("unsupported service-kit upgrade {from} -> {to}"))
        })
}

fn decode_legacy_state(source: &str) -> Result<LegacyProjectState, ManagerError> {
    let state: LegacyProjectState = toml::from_str(source).map_err(|error| {
        ManagerError::InvalidProject(format!(
            "invalid private schema-1 `{PROJECT_STATE_PATH}`: {error}"
        ))
    })?;
    if state.schema_version != 1 {
        return Err(ManagerError::InvalidProject(format!(
            "unsupported legacy project state schema version {}; expected 1",
            state.schema_version
        )));
    }
    Ok(state)
}

fn parse_frozen_baseline(recipe: &FrozenRecipe) -> Result<FrozenBaseline, ManagerError> {
    #[cfg(test)]
    if recipe.public.from == TEST_LEGACY_VERSION {
        let baseline = test_frozen_baseline();
        validate_frozen_baseline(recipe, &baseline)?;
        return Ok(baseline);
    }
    let baseline: FrozenBaseline = serde_json::from_str(recipe.baseline).map_err(|error| {
        ManagerError::InvalidProject(format!(
            "compiled schema-1 {} baseline is invalid: {error}",
            recipe.public.from
        ))
    })?;
    validate_frozen_baseline(recipe, &baseline)?;
    Ok(baseline)
}

fn validate_frozen_baseline(
    recipe: &FrozenRecipe,
    baseline: &FrozenBaseline,
) -> Result<(), ManagerError> {
    if baseline.schema_version != 1 || baseline.captured_release != recipe.public.from {
        return Err(ManagerError::InvalidProject(format!(
            "compiled schema-1 baseline identity mismatch for {}",
            recipe.public.from
        )));
    }
    if baseline.fixture_service.is_empty() {
        return Err(ManagerError::InvalidProject(format!(
            "compiled schema-1 {} baseline has no fixture service",
            recipe.public.from
        )));
    }

    let mut paths = BTreeSet::new();
    for file in &baseline.files {
        validate_relative_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} baseline contains duplicate path `{}`",
                recipe.public.from, file.path
            )));
        }
        if !valid_sha256(&file.sha256) || !valid_sha256(&file.normalized_sha256) {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} baseline has an invalid hash for `{}`",
                recipe.public.from, file.path
            )));
        }
    }

    let mut byte_paths = BTreeSet::new();
    for path in &baseline.baseline_byte_paths {
        if !byte_paths.insert(path.as_str()) {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} baseline contains duplicate byte path `{path}`",
                recipe.public.from
            )));
        }
        let file = baseline
            .files
            .iter()
            .find(|file| file.path == *path)
            .ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "compiled schema-1 {} byte path `{path}` has no file record",
                    recipe.public.from
                ))
            })?;
        if !baseline.content_blobs.contains_key(&file.normalized_sha256) {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} byte path `{path}` has no frozen content",
                recipe.public.from
            )));
        }
    }
    for (hash, blob) in &baseline.content_blobs {
        if !valid_sha256(hash) || sha256_hex(blob.text.as_bytes()) != *hash {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} content blob `{hash}` is corrupt",
                recipe.public.from
            )));
        }
    }
    if baseline
        .module_versions
        .values()
        .any(|version| version != recipe.module_version)
    {
        return Err(ManagerError::InvalidProject(format!(
            "compiled schema-1 {} module-version map is inconsistent",
            recipe.public.from
        )));
    }
    for (profile_id, profile) in &baseline.profiles {
        if profile
            .modules
            .iter()
            .any(|id| !baseline.module_versions.contains_key(id))
        {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} profile `{profile_id}` selects an unknown module",
                recipe.public.from
            )));
        }
        if profile
            .runtime_disabled_modules
            .iter()
            .any(|id| !profile.modules.contains(id))
        {
            return Err(ManagerError::InvalidProject(format!(
                "compiled schema-1 {} profile `{profile_id}` disables an unselected module",
                recipe.public.from
            )));
        }
    }
    Ok(())
}

fn validate_legacy_state(
    legacy: &LegacyProjectState,
    recipe: &FrozenRecipe,
    baseline: &FrozenBaseline,
) -> Result<(), ManagerError> {
    validate_legacy_identity_and_profile(legacy, recipe)?;
    let actual_modules = validate_legacy_modules(legacy, baseline)?;
    validate_legacy_provider_membership(legacy, &actual_modules)?;
    let expected_state = frozen_state_template(baseline)?;
    validate_legacy_provider_assertions(legacy, &expected_state)?;
    validate_unique_values(
        &legacy.retained_compose_volumes,
        "legacy retained Compose volume",
    )?;
    validate_legacy_ownership(legacy, &expected_state, baseline)?;
    validate_legacy_regions(legacy, &expected_state)?;
    Ok(())
}
fn validate_legacy_identity_and_profile(
    legacy: &LegacyProjectState,
    recipe: &FrozenRecipe,
) -> Result<(), ManagerError> {
    if legacy.kit_version != recipe.public.from {
        return Err(ManagerError::InvalidProject(format!(
            "legacy state kit version `{}` does not match recipe source `{}`",
            legacy.kit_version, recipe.public.from
        )));
    }
    if legacy.profile.version != recipe.profile_version {
        return Err(ManagerError::InvalidProject(format!(
            "legacy profile `{}` has version `{}`; expected `{}`",
            legacy.profile.id, legacy.profile.version, recipe.profile_version
        )));
    }
    if legacy.service.is_empty() || legacy.service == PROJECT_NAME_PLACEHOLDER {
        return Err(ManagerError::InvalidProject(
            "legacy state has an invalid service name".to_owned(),
        ));
    }
    validate_unique_values(&legacy.profile.additions, "legacy profile addition")?;
    validate_unique_values(&legacy.profile.removals, "legacy profile removal")?;
    if let Some(id) = legacy
        .profile
        .additions
        .iter()
        .find(|id| legacy.profile.removals.contains(id))
    {
        return Err(ManagerError::InvalidProject(format!(
            "legacy module `{id}` appears in both profile additions and removals"
        )));
    }
    Ok(())
}

fn validate_legacy_modules(
    legacy: &LegacyProjectState,
    baseline: &FrozenBaseline,
) -> Result<BTreeSet<String>, ManagerError> {
    let profile = baseline.profiles.get(&legacy.profile.id).ok_or_else(|| {
        ManagerError::InvalidProject(format!(
            "legacy state selects unknown frozen profile `{}`",
            legacy.profile.id
        ))
    })?;
    let mut expected_modules = profile.modules.iter().cloned().collect::<BTreeSet<_>>();
    for id in &legacy.profile.removals {
        if !baseline.module_versions.contains_key(id) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy profile removes unknown module `{id}`"
            )));
        }
        expected_modules.remove(id);
    }
    for id in &legacy.profile.additions {
        if !baseline.module_versions.contains_key(id) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy profile adds unknown module `{id}`"
            )));
        }
        expected_modules.insert(id.clone());
    }

    let mut actual_modules = BTreeSet::new();
    for module in &legacy.modules {
        if !actual_modules.insert(module.id.clone()) {
            return Err(ManagerError::InvalidProject(format!(
                "duplicate legacy selected module `{}`",
                module.id
            )));
        }
        let expected_version = baseline.module_versions.get(&module.id).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "legacy state selects unknown frozen module `{}`",
                module.id
            ))
        })?;
        if module.version != *expected_version {
            return Err(ManagerError::InvalidProject(format!(
                "legacy module `{}` has version `{}`; expected `{expected_version}`",
                module.id, module.version
            )));
        }
    }
    if actual_modules != expected_modules {
        return Err(ManagerError::InvalidProject(format!(
            "legacy selected modules do not match frozen profile `{}` plus its additions/removals",
            legacy.profile.id
        )));
    }
    Ok(actual_modules)
}

fn validate_legacy_provider_membership(
    legacy: &LegacyProjectState,
    actual_modules: &BTreeSet<String>,
) -> Result<(), ManagerError> {
    let mut provider_slots = BTreeSet::new();
    for provider in &legacy.providers {
        if !provider_slots.insert(provider.slot.as_str()) {
            return Err(ManagerError::InvalidProject(format!(
                "duplicate legacy provider slot `{}`",
                provider.slot
            )));
        }
        if !actual_modules.contains(&provider.module) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy provider slot `{}` selects uninstalled module `{}`",
                provider.slot, provider.module
            )));
        }
    }
    Ok(())
}

fn validate_legacy_provider_assertions(
    legacy: &LegacyProjectState,
    expected: &LegacyProjectState,
) -> Result<(), ManagerError> {
    let expected_providers = expected
        .providers
        .iter()
        .map(|provider| (&provider.slot, &provider.module))
        .collect::<BTreeMap<_, _>>();
    let actual_providers = legacy
        .providers
        .iter()
        .map(|provider| (&provider.slot, &provider.module))
        .collect::<BTreeMap<_, _>>();
    if actual_providers != expected_providers {
        return Err(ManagerError::InvalidProject(
            "legacy provider assertions do not match the frozen release map".to_owned(),
        ));
    }
    Ok(())
}

fn frozen_state_template(baseline: &FrozenBaseline) -> Result<LegacyProjectState, ManagerError> {
    let state_file = baseline
        .files
        .iter()
        .find(|file| file.path == PROJECT_STATE_PATH)
        .ok_or_else(|| {
            ManagerError::InvalidProject(
                "compiled schema-1 baseline has no project-state record".to_owned(),
            )
        })?;
    let source = baseline
        .content_blobs
        .get(&state_file.normalized_sha256)
        .ok_or_else(|| {
            ManagerError::InvalidProject(
                "compiled schema-1 baseline has no project-state content".to_owned(),
            )
        })?;
    decode_legacy_state(&source.text)
}

fn validate_legacy_ownership(
    legacy: &LegacyProjectState,
    expected: &LegacyProjectState,
    baseline: &FrozenBaseline,
) -> Result<(), ManagerError> {
    let expected_ownership = ownership_map(&expected.ownership, "compiled schema-1 baseline")?;
    let actual_ownership = ownership_map(&legacy.ownership, "legacy state")?;
    for (path, kind) in &actual_ownership {
        let file = baseline
            .files
            .iter()
            .find(|file| file.path == *path)
            .ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "legacy state contains unknown ownership path `{path}`"
                ))
            })?;
        if !class_matches_legacy(file.class, *kind) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy ownership for `{path}` is relabelled from its frozen class"
            )));
        }
    }
    if let Some(path) = expected_ownership
        .keys()
        .find(|path| !actual_ownership.contains_key(*path))
    {
        return Err(ManagerError::InvalidProject(format!(
            "legacy state is missing ownership record `{path}`"
        )));
    }
    if let Some(path) = actual_ownership
        .keys()
        .find(|path| !expected_ownership.contains_key(*path))
    {
        return Err(ManagerError::InvalidProject(format!(
            "legacy state contains unknown ownership record `{path}`"
        )));
    }
    for (path, expected_kind) in expected_ownership {
        if actual_ownership.get(path) != Some(&expected_kind) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy ownership for `{path}` is relabelled from its frozen class"
            )));
        }
    }
    Ok(())
}

fn ownership_map<'a>(
    records: &'a [LegacyOwnershipRecord],
    label: &str,
) -> Result<BTreeMap<&'a str, LegacyOwnershipKind>, ManagerError> {
    let mut ownership = BTreeMap::new();
    for record in records {
        validate_relative_path(&record.path)?;
        if ownership
            .insert(record.path.as_str(), record.kind)
            .is_some()
        {
            return Err(ManagerError::InvalidProject(format!(
                "{label} contains duplicate ownership path `{}`",
                record.path
            )));
        }
    }
    Ok(ownership)
}

fn validate_legacy_regions(
    legacy: &LegacyProjectState,
    expected: &LegacyProjectState,
) -> Result<(), ManagerError> {
    let mut actual = legacy.managed_regions.iter().collect::<Vec<_>>();
    actual.sort();
    if actual.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(ManagerError::InvalidProject(
            "legacy state contains duplicate managed-region ids".to_owned(),
        ));
    }
    for region in &actual {
        validate_relative_path(&region.path)?;
        if region.marker_version != MANAGED_MARKER_VERSION || !valid_sha256(&region.content_hash) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy managed region `{}` has invalid metadata",
                region.id
            )));
        }
    }
    let mut frozen = expected.managed_regions.iter().collect::<Vec<_>>();
    frozen.sort();
    if actual != frozen {
        return Err(ManagerError::InvalidProject(
            "legacy managed-region assertions do not match the frozen release map".to_owned(),
        ));
    }
    Ok(())
}

fn class_matches_legacy(class: FrozenOwnershipClass, kind: LegacyOwnershipKind) -> bool {
    matches!(
        (class, kind),
        (
            FrozenOwnershipClass::KitOwned,
            LegacyOwnershipKind::KitOwned
        ) | (FrozenOwnershipClass::Derived, LegacyOwnershipKind::Derived)
            | (
                FrozenOwnershipClass::ApplicationOwned,
                LegacyOwnershipKind::ApplicationOwned
            )
    )
}

fn validate_source_file_map(
    legacy: &LegacyProjectState,
    baseline: &FrozenBaseline,
    files: &BTreeMap<String, String>,
    lockfile: Option<&[u8]>,
) -> Result<(), ManagerError> {
    if lockfile.is_none() {
        return Err(ManagerError::InvalidProject(
            "legacy project is missing required dependency lock `Cargo.lock`".to_owned(),
        ));
    }
    for record in &baseline.files {
        if record.path == "Cargo.lock" {
            continue;
        }
        let contents = files.get(&record.path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "legacy project is missing frozen path `{}`",
                record.path
            ))
        })?;
        if record.path == PROJECT_STATE_PATH
            || matches!(
                record.class,
                FrozenOwnershipClass::ApplicationOwned | FrozenOwnershipClass::DependencyLock
            )
        {
            continue;
        }
        let normalized = contents.replace(&legacy.service, PROJECT_NAME_PLACEHOLDER);
        if sha256_hex(normalized.as_bytes()) != record.normalized_sha256 {
            return Err(ManagerError::InvalidProject(format!(
                "legacy-baseline-mismatch: controlled path `{}` differs from the project-name-normalized frozen {} baseline",
                record.path, baseline.captured_release
            )));
        }
    }
    Ok(())
}

fn target_state_skeleton(
    legacy: &LegacyProjectState,
    target_release: &ReleaseIdentity,
    catalog: &ModuleCatalog,
) -> Result<ProjectState, ManagerError> {
    let base_files =
        render_embedded_base_files(&legacy.service, &legacy.profile.id, target_release)
            .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    let source = base_files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject("target renderer omitted project state".to_owned())
    })?;
    let mut state = ProjectState::parse(source)?;
    let selected = target_selection(legacy, catalog)?;
    let ordered = catalog.composition_order(&selected)?;
    let (additions, removals) = target_profile_delta(&legacy.profile.id, &selected)?;
    state.framework = target_release.clone();
    state.profile = ProfileSelection {
        id: legacy.profile.id.clone(),
        version: catalog.bundle_version.clone(),
        additions,
        removals,
    };
    state.modules = ordered
        .iter()
        .map(|module| SelectedModule {
            id: module.id.clone(),
            version: module.version.clone(),
        })
        .collect();
    state.providers = ordered
        .iter()
        .filter_map(|module| {
            module.provider_slot.as_ref().map(|slot| SelectedProvider {
                slot: slot.clone(),
                module: module.id.clone(),
            })
        })
        .collect();
    state
        .retained_compose_volumes
        .clone_from(&legacy.retained_compose_volumes);
    retain_selected_compose_volumes(&mut state, catalog)?;
    state.retained_compose_volumes.sort();
    state.retained_compose_volumes.dedup();
    state.ownership = vec![OwnershipRecord {
        path: "Cargo.lock".to_owned(),
        kind: OwnershipKind::DependencyLock,
        approved_sha256: None,
    }];
    state.managed_regions.sort();
    Ok(state)
}

fn target_selection(
    legacy: &LegacyProjectState,
    catalog: &ModuleCatalog,
) -> Result<BTreeSet<String>, ManagerError> {
    let resolved = resolve_profile(&legacy.profile.id)
        .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    let mut selected = resolved.modules().iter().cloned().collect::<BTreeSet<_>>();
    for id in &legacy.profile.removals {
        if matches!(id.as_str(), "generator" | "test-support") {
            continue;
        }
        let definition = catalog.module(id).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "legacy profile removal `{id}` has no target catalog definition"
            ))
        })?;
        if definition.kind == "tooling" {
            continue;
        }
        selected = catalog.resolve_remove(&selected, id)?;
    }
    for id in &legacy.profile.additions {
        if matches!(id.as_str(), "generator" | "test-support") {
            continue;
        }
        let definition = catalog.module(id).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "legacy profile addition `{id}` has no target catalog definition"
            ))
        })?;
        if definition.kind == "tooling" {
            continue;
        }
        selected = catalog.resolve_add(&selected, id)?;
    }
    catalog.validate_selection(&selected)?;
    Ok(selected)
}

fn target_profile_delta(
    profile_id: &str,
    selected: &BTreeSet<String>,
) -> Result<(Vec<String>, Vec<String>), ManagerError> {
    let resolved = resolve_profile(profile_id)
        .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    let profile_modules = resolved.modules().iter().cloned().collect::<BTreeSet<_>>();
    let additions = selected
        .difference(&profile_modules)
        .cloned()
        .collect::<Vec<_>>();
    let removals = profile_modules
        .difference(selected)
        .cloned()
        .collect::<Vec<_>>();
    Ok((additions, removals))
}

fn build_target_project(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    legacy: &LegacyProjectState,
    baseline: &FrozenBaseline,
) -> Result<TargetProject, ManagerError> {
    let base_files = render_embedded_base_files(
        &legacy.service,
        &legacy.profile.id,
        &snapshot.release_identity,
    )
    .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    build_target_project_with_files(
        catalog,
        snapshot,
        legacy,
        baseline,
        &snapshot.files,
        base_files,
    )
}

fn build_target_project_with_files(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    legacy: &LegacyProjectState,
    baseline: &FrozenBaseline,
    source_files: &BTreeMap<String, String>,
    base_files: BTreeMap<String, String>,
) -> Result<TargetProject, ManagerError> {
    let mut state = target_state_skeleton(legacy, &snapshot.release_identity, catalog)?;
    let selected = state
        .modules
        .iter()
        .map(|module| module.id.clone())
        .collect::<BTreeSet<_>>();
    let mut target_files = base_files.clone();
    target_files.remove(PROJECT_STATE_PATH);

    let source_classes = baseline
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.class))
        .collect::<BTreeMap<_, _>>();
    let mut ownership = vec![OwnershipRecord {
        path: "Cargo.lock".to_owned(),
        kind: OwnershipKind::DependencyLock,
        approved_sha256: None,
    }];
    let base_paths = target_files.keys().cloned().collect::<Vec<_>>();
    for path in base_paths {
        let kind = target_base_ownership(&path);
        if kind == OwnershipKind::ApplicationOwned
            && source_classes.get(path.as_str()) == Some(&FrozenOwnershipClass::ApplicationOwned)
            && let Some(current) = source_files.get(&path)
        {
            target_files.insert(path.clone(), current.clone());
        }
        ownership.push(OwnershipRecord {
            path,
            kind,
            approved_sha256: None,
        });
    }

    install_target_application_templates(
        catalog,
        &selected,
        source_files,
        &source_classes,
        &mut target_files,
        &mut ownership,
    )?;

    for path in MANAGER_DERIVED_PATHS {
        let contents = render_derived_with_retained_volumes(
            path,
            catalog,
            &selected,
            &state.service,
            &state.retained_compose_volumes,
        )?;
        target_files.insert((*path).to_owned(), contents);
        push_target_ownership(&mut ownership, path, OwnershipKind::Derived)?;
    }

    for record in baseline
        .files
        .iter()
        .filter(|record| record.class == FrozenOwnershipClass::ApplicationOwned)
    {
        if final_shape_forbidden(&record.path, baseline) {
            return Err(ManagerError::InvalidProject(format!(
                "application-owned legacy path `{}` is forbidden by the thin target layout; relocate it before updating",
                record.path
            )));
        }
        push_target_ownership(
            &mut ownership,
            &record.path,
            OwnershipKind::ApplicationOwned,
        )?;
    }
    for path in source_files.keys().filter(|path| {
        !source_classes.contains_key(path.as_str()) && is_application_migration(path)
    }) {
        push_target_ownership(&mut ownership, path, OwnershipKind::ApplicationOwned)?;
    }

    state.ownership = ownership;
    for path in ["Cargo.toml", "apps/service/src/composition.rs"] {
        let content = target_files.remove(path).ok_or_else(|| {
            ManagerError::InvalidProject(format!("target renderer omitted managed file `{path}`"))
        })?;
        let reconciled =
            reconcile_target_regions(catalog, snapshot, &mut state, path, content, &selected)?;
        target_files.insert(path.to_owned(), reconciled);
    }
    refresh_target_hashes(&mut state, &target_files)?;
    state.ownership.sort();
    state.managed_regions.sort();
    state.validate()?;

    Ok(TargetProject {
        state,
        files: target_files,
        base_files,
    })
}

fn install_target_application_templates(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    source_files: &BTreeMap<String, String>,
    source_classes: &BTreeMap<&str, FrozenOwnershipClass>,
    target_files: &mut BTreeMap<String, String>,
    ownership: &mut Vec<OwnershipRecord>,
) -> Result<(), ManagerError> {
    for module in catalog.composition_order(selected)? {
        for path in &module.application_templates {
            let descriptor = application_template(&module.id, path).ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "target application template `{path}` for module `{}` is not embedded",
                    module.id
                ))
            })?;
            let contents = match source_classes.get(path.as_str()) {
                Some(FrozenOwnershipClass::ApplicationOwned) => source_files
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| descriptor.source.to_owned()),
                Some(_) => descriptor.source.to_owned(),
                None => source_files
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| descriptor.source.to_owned()),
            };
            target_files.insert(path.clone(), contents);
            push_target_ownership(ownership, path, OwnershipKind::ApplicationOwned)?;
        }
    }
    Ok(())
}

fn target_base_ownership(path: &str) -> OwnershipKind {
    if TARGET_APPLICATION_PATHS.contains(&path) {
        OwnershipKind::ApplicationOwned
    } else {
        OwnershipKind::KitOwned
    }
}

fn push_target_ownership(
    ownership: &mut Vec<OwnershipRecord>,
    path: &str,
    kind: OwnershipKind,
) -> Result<(), ManagerError> {
    if let Some(existing) = ownership.iter().find(|record| record.path == path) {
        if existing.kind != kind {
            return Err(ManagerError::InvalidProject(format!(
                "target ownership for `{path}` conflicts between `{:?}` and `{kind:?}`",
                existing.kind
            )));
        }
        return Ok(());
    }
    ownership.push(OwnershipRecord {
        path: path.to_owned(),
        kind,
        approved_sha256: None,
    });
    Ok(())
}

fn reconcile_target_regions(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    state: &mut ProjectState,
    path: &str,
    mut content: String,
    selected: &BTreeSet<String>,
) -> Result<String, ManagerError> {
    let ids = state
        .managed_regions
        .iter()
        .filter(|record| record.path == path)
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    for id in ids {
        let regions = parse_managed_regions(&content)?;
        let region = regions
            .iter()
            .find(|region| region.id == id)
            .ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "target baseline `{path}` is missing managed region `{id}`"
                ))
            })?;
        let current = ManagedRegionRecord {
            id: id.clone(),
            path: path.to_owned(),
            marker_version: region.marker_version,
            content_hash: region.content_hash.to_owned(),
        };
        let desired = render_region(catalog, &id, selected, snapshot)?;
        content = reconcile_managed_region(&content, &current, &desired)?;
        let record = state
            .managed_regions
            .iter_mut()
            .find(|record| record.path == path && record.id == id)
            .ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "target state lost managed region `{id}` in `{path}`"
                ))
            })?;
        record.content_hash = sha256_hex(desired.as_bytes());
    }
    Ok(content)
}

fn refresh_target_hashes(
    state: &mut ProjectState,
    files: &BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    for record in &mut state.ownership {
        record.approved_sha256 = match record.kind {
            OwnershipKind::KitOwned | OwnershipKind::Derived => {
                let contents = files.get(&record.path).ok_or_else(|| {
                    ManagerError::InvalidProject(format!(
                        "target ownership references missing controlled file `{}`",
                        record.path
                    ))
                })?;
                Some(sha256_hex(contents.as_bytes()))
            }
            OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock => None,
        };
    }
    Ok(())
}

fn build_upgrade_operations(
    snapshot: &ProjectSnapshot,
    legacy: &LegacyProjectState,
    baseline: &FrozenBaseline,
    target: &TargetProject,
) -> Result<Vec<PlanOperation>, ManagerError> {
    let mut operations = Vec::new();
    append_frozen_path_operations(snapshot, baseline, target, &mut operations)?;
    let source_records = baseline
        .files
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    append_new_target_path_operations(snapshot, target, &source_records, &mut operations)?;

    let state_content = target.state.to_toml()?;
    let current_state = snapshot.files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject(format!("missing required `{PROJECT_STATE_PATH}`"))
    })?;
    operations.push(PlanOperation::WriteState {
        path: PROJECT_STATE_PATH.to_owned(),
        expected_hash: sha256_hex(current_state.as_bytes()),
        content_hash: sha256_hex(state_content.as_bytes()),
        content: state_content,
    });

    if operations.len() == 1 {
        return Err(ManagerError::InvalidProject(format!(
            "schema-1 {} upgrade unexpectedly produced no layout changes",
            legacy.kit_version
        )));
    }
    if operations.iter().any(|operation| {
        matches!(
            operation,
            PlanOperation::WriteLock { .. } | PlanOperation::WriteResolvedLock { .. }
        )
    }) {
        return Err(ManagerError::InvalidProject(
            "pure schema-1 upgrade planning must not emit a Cargo.lock operation".to_owned(),
        ));
    }
    Ok(operations)
}

fn append_frozen_path_operations(
    snapshot: &ProjectSnapshot,
    baseline: &FrozenBaseline,
    target: &TargetProject,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    for record in &baseline.files {
        if matches!(record.path.as_str(), PROJECT_STATE_PATH | "Cargo.lock") {
            continue;
        }
        let current = snapshot.files.get(&record.path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "legacy project is missing frozen path `{}`",
                record.path
            ))
        })?;
        if record.class == FrozenOwnershipClass::ApplicationOwned {
            if target
                .state
                .ownership_of(&record.path)
                .is_some_and(|kind| kind != OwnershipKind::ApplicationOwned)
            {
                return Err(ManagerError::InvalidProject(format!(
                    "application-owned legacy path `{}` collides with target-controlled output; relocate it before updating",
                    record.path
                )));
            }
            continue;
        }
        if record.class == FrozenOwnershipClass::DependencyLock {
            continue;
        }
        match target.files.get(&record.path) {
            Some(contents) if contents == current => {}
            Some(contents) => {
                push_replacement(operations, &target.state, &record.path, current, contents);
            }
            None => operations.push(PlanOperation::RemoveFile {
                path: record.path.clone(),
                expected_hash: sha256_hex(current.as_bytes()),
            }),
        }
    }
    Ok(())
}

fn append_new_target_path_operations(
    snapshot: &ProjectSnapshot,
    target: &TargetProject,
    source_records: &BTreeMap<&str, &FrozenFileRecord>,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    for (path, contents) in &target.files {
        if source_records.contains_key(path.as_str()) {
            continue;
        }
        match snapshot.files.get(path) {
            Some(current)
                if target.state.ownership_of(path) == Some(OwnershipKind::ApplicationOwned) =>
            {
                if current != contents {
                    return Err(ManagerError::InvalidProject(format!(
                        "target application-owned path `{path}` was not preserved during planning"
                    )));
                }
            }
            Some(_) => {
                return Err(ManagerError::InvalidProject(format!(
                    "target-controlled path `{path}` already exists outside the frozen legacy inventory"
                )));
            }
            None if target.state.ownership_of(path) == Some(OwnershipKind::Derived) => {
                operations.push(PlanOperation::RegenerateDerived {
                    path: path.clone(),
                    expected_hash: None,
                    content_hash: sha256_hex(contents.as_bytes()),
                    content: contents.clone(),
                });
            }
            None => operations.push(PlanOperation::CreateFile {
                path: path.clone(),
                content_hash: sha256_hex(contents.as_bytes()),
                content: contents.clone(),
            }),
        }
    }
    Ok(())
}

fn validate_pure_legacy_plan(plan: &ManagementPlan) -> Result<(), ManagerError> {
    if plan.operations.iter().any(|operation| {
        matches!(
            operation,
            PlanOperation::WriteLock { .. } | PlanOperation::WriteResolvedLock { .. }
        )
    }) {
        return Err(ManagerError::InvalidProject(
            "pure schema-1 upgrade planning emitted a Cargo.lock operation".to_owned(),
        ));
    }
    let state_writes = plan
        .operations
        .iter()
        .filter(|operation| matches!(operation, PlanOperation::WriteState { .. }))
        .count();
    if state_writes != 1
        || !matches!(
            plan.operations.last(),
            Some(PlanOperation::WriteState { .. })
        )
    {
        return Err(ManagerError::InvalidProject(
            "pure schema-1 upgrade planning must emit exactly one final state write".to_owned(),
        ));
    }
    Ok(())
}

fn push_replacement(
    operations: &mut Vec<PlanOperation>,
    state: &ProjectState,
    path: &str,
    current: &str,
    target: &str,
) {
    let expected_hash = sha256_hex(current.as_bytes());
    let content_hash = sha256_hex(target.as_bytes());
    if state.ownership_of(path) == Some(OwnershipKind::Derived) {
        operations.push(PlanOperation::RegenerateDerived {
            path: path.to_owned(),
            expected_hash: Some(expected_hash),
            content_hash,
            content: target.to_owned(),
        });
    } else {
        operations.push(PlanOperation::ReplaceKitFile {
            path: path.to_owned(),
            expected_hash,
            content_hash,
            content: target.to_owned(),
        });
    }
}

fn preserved_paths(catalog: &ModuleCatalog, state: &ProjectState) -> Vec<String> {
    let mut preserved = state
        .ownership
        .iter()
        .filter(|record| {
            record.kind == OwnershipKind::ApplicationOwned
                || preserves_historical_path(&record.path)
        })
        .map(|record| record.path.clone())
        .collect::<BTreeSet<_>>();
    for module in &state.modules {
        if let Some(definition) = catalog.module(&module.id) {
            preserved.extend(definition.persistence.iter().cloned());
        }
    }
    preserved.into_iter().collect()
}

fn read_extra_application_migrations(
    project_root: &Path,
    baseline: &FrozenBaseline,
    files: &mut BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    let migration_root = project_root.join("migrations");
    let mut discovered = Vec::new();
    let mut discovered_directories = Vec::new();
    collect_regular_files(
        project_root,
        &migration_root,
        &mut discovered,
        &mut discovered_directories,
    )?;
    if let Some(path) = discovered_directories.first() {
        return Err(ManagerError::InvalidProject(format!(
            "unexpected legacy migration directory `{path}`; application migrations must be direct regular files"
        )));
    }
    let baseline_paths = baseline
        .files
        .iter()
        .map(|record| record.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut versions = BTreeSet::new();
    for path in discovered {
        if baseline_paths.contains(path.as_str()) {
            if is_application_migration(&path) {
                let version = application_migration_version(&path)?;
                if !versions.insert(version) {
                    return Err(ManagerError::InvalidProject(format!(
                        "duplicate application migration version {version}"
                    )));
                }
            }
            continue;
        }
        if !is_application_migration(&path) {
            return Err(ManagerError::InvalidProject(format!(
                "unexpected legacy migration `{path}`; only forward application SQL in the reserved high range may be preserved"
            )));
        }
        let version = application_migration_version(&path)?;
        if !versions.insert(version) {
            return Err(ManagerError::InvalidProject(format!(
                "duplicate application migration version {version}"
            )));
        }
        let bytes = read_required_regular(project_root, &path)?;
        files.insert(path.clone(), utf8_file(&path, bytes)?);
    }
    Ok(())
}

fn application_migration_version(path: &str) -> Result<u64, ManagerError> {
    let file_name = path.strip_prefix("migrations/").ok_or_else(|| {
        ManagerError::InvalidProject(format!("invalid application migration path `{path}`"))
    })?;
    if file_name.contains('/')
        || !Path::new(file_name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
    {
        return Err(ManagerError::InvalidProject(format!(
            "invalid application migration path `{path}`"
        )));
    }
    let (version, description) = file_name.split_once('_').ok_or_else(|| {
        ManagerError::InvalidProject(format!(
            "application migration `{path}` must use `<version>_<description>.sql`"
        ))
    })?;
    if description.eq_ignore_ascii_case(".sql")
        || ends_with_ignore_ascii_case(description, ".up.sql")
        || ends_with_ignore_ascii_case(description, ".down.sql")
    {
        return Err(ManagerError::InvalidProject(format!(
            "application migration `{path}` is not a canonical forward migration"
        )));
    }
    let version = version.parse::<u64>().map_err(|_| {
        ManagerError::InvalidProject(format!(
            "application migration `{path}` has an invalid version"
        ))
    })?;
    if !(APPLICATION_MIGRATION_MIN..=APPLICATION_MIGRATION_MAX).contains(&version) {
        return Err(ManagerError::InvalidProject(format!(
            "application migration `{path}` is outside the reserved application range"
        )));
    }
    Ok(version)
}

fn is_application_migration(path: &str) -> bool {
    path.starts_with("migrations/")
        && Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
        && application_migration_version(path).is_ok()
}
fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix))
}

fn scan_legacy_forbidden_roots(
    project_root: &Path,
    baseline: &FrozenBaseline,
) -> Result<(), ManagerError> {
    let expected = baseline
        .files
        .iter()
        .map(|record| record.path.as_str())
        .collect::<BTreeSet<_>>();
    let expected_directories = baseline
        .files
        .iter()
        .flat_map(|record| {
            record
                .path
                .match_indices('/')
                .map(|(index, _)| &record.path[..index])
        })
        .collect::<BTreeSet<_>>();
    let mut roots = BTreeSet::from([
        ".sqlx".to_owned(),
        "specs".to_owned(),
        "templates".to_owned(),
        "xtask".to_owned(),
    ]);
    for record in &baseline.files {
        if let Some(root) = legacy_crate_root(&record.path) {
            roots.insert(root);
        }
    }
    for root in roots {
        let absolute = project_root.join(&root);
        if !absolute.exists() {
            continue;
        }
        if !expected_directories.contains(root.as_str()) {
            return Err(ManagerError::InvalidProject(format!(
                "unknown directory `{root}` is forbidden in the legacy framework tree; remove it before updating"
            )));
        }
        let mut discovered = Vec::new();
        let mut discovered_directories = Vec::new();
        collect_regular_files(
            project_root,
            &absolute,
            &mut discovered,
            &mut discovered_directories,
        )?;
        if let Some(path) = discovered
            .iter()
            .find(|path| !expected.contains(path.as_str()))
        {
            return Err(ManagerError::InvalidProject(format!(
                "application-owned bytes at legacy framework path `{path}` cannot be preserved in the thin layout; relocate them before updating"
            )));
        }
        if let Some(path) = discovered_directories
            .iter()
            .find(|path| !expected_directories.contains(path.as_str()))
        {
            return Err(ManagerError::InvalidProject(format!(
                "unknown empty directory `{path}` is forbidden in the legacy framework tree; remove it before updating"
            )));
        }
    }
    Ok(())
}

fn final_shape_forbidden(path: &str, baseline: &FrozenBaseline) -> bool {
    path == ".sqlx"
        || path.starts_with(".sqlx/")
        || path == "specs"
        || path.starts_with("specs/")
        || path == "templates"
        || path.starts_with("templates/")
        || path == "xtask"
        || path.starts_with("xtask/")
        || baseline.files.iter().any(|record| {
            legacy_crate_root(&record.path)
                .is_some_and(|root| path == root || path.starts_with(&format!("{root}/")))
        })
}

fn legacy_crate_root(path: &str) -> Option<String> {
    let mut components = path.split('/');
    if components.next()? != "crates" {
        return None;
    }
    let crate_name = components.next()?;
    Some(format!("crates/{crate_name}"))
}

fn read_existing_target_application_files(
    project_root: &Path,
    state: &ProjectState,
    baseline: &FrozenBaseline,
    source_files: &mut BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    for record in state
        .ownership
        .iter()
        .filter(|record| record.kind == OwnershipKind::ApplicationOwned)
    {
        if baseline.files.iter().any(|file| file.path == record.path) {
            continue;
        }
        let absolute = project_root.join(&record.path);
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(ManagerError::InvalidProject(format!(
                        "target application path `{}` is not a regular file",
                        record.path
                    )));
                }
                let bytes = read_required_regular(project_root, &record.path)?;
                source_files.insert(record.path.clone(), utf8_file(&record.path, bytes)?);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ManagerError::Filesystem {
                    path: absolute,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn reject_symlink_root(project_root: &Path) -> Result<(), ManagerError> {
    let metadata =
        fs::symlink_metadata(project_root).map_err(|source| ManagerError::Filesystem {
            path: project_root.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ManagerError::InvalidProject(format!(
            "legacy project root `{}` must be a real directory, not a symlink",
            project_root.display()
        )));
    }
    Ok(())
}

fn read_required_regular(project_root: &Path, relative: &str) -> Result<Vec<u8>, ManagerError> {
    validate_relative_path(relative)?;
    reject_symlink_components(project_root, relative)?;
    let path = project_root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ManagerError::InvalidProject(format!("legacy project is missing `{relative}`"))
        } else {
            ManagerError::Filesystem {
                path: path.clone(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ManagerError::InvalidProject(format!(
            "legacy path `{relative}` must be a regular file and must not be a symlink"
        )));
    }
    fs::read(&path).map_err(|source| ManagerError::Filesystem { path, source })
}

fn reject_symlink_components(project_root: &Path, relative: &str) -> Result<(), ManagerError> {
    let mut current = project_root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            return Err(ManagerError::InvalidProject(format!(
                "unsafe legacy project path `{relative}`"
            )));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ManagerError::InvalidProject(format!(
                    "legacy path `{relative}` traverses symlink `{}`",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(ManagerError::Filesystem {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn collect_regular_files(
    project_root: &Path,
    directory: &Path,
    output: &mut Vec<String>,
    directories: &mut Vec<String>,
) -> Result<(), ManagerError> {
    let metadata = fs::symlink_metadata(directory).map_err(|source| ManagerError::Filesystem {
        path: directory.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ManagerError::InvalidProject(format!(
            "legacy path `{}` must be a real directory",
            directory.display()
        )));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|source| ManagerError::Filesystem {
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ManagerError::Filesystem {
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ManagerError::Filesystem {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ManagerError::InvalidProject(format!(
                "legacy tree contains symlink `{}`",
                path.display()
            )));
        }
        if metadata.is_dir() {
            let relative = path.strip_prefix(project_root).map_err(|_| {
                ManagerError::InvalidProject(format!(
                    "legacy path `{}` escapes the project root",
                    path.display()
                ))
            })?;
            let relative = relative.to_str().ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "legacy project contains a non-UTF-8 directory under `{}`",
                    directory.display()
                ))
            })?;
            directories.push(relative.replace('\\', "/"));
            collect_regular_files(project_root, &path, output, directories)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ManagerError::InvalidProject(format!(
                "legacy tree contains unsupported filesystem entry `{}`",
                path.display()
            )));
        }
        let relative = path.strip_prefix(project_root).map_err(|_| {
            ManagerError::InvalidProject(format!(
                "legacy path `{}` escapes the project root",
                path.display()
            ))
        })?;
        let relative = relative.to_str().ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "legacy project contains a non-UTF-8 path under `{}`",
                directory.display()
            ))
        })?;
        validate_relative_path(relative)?;
        output.push(relative.replace(std::path::MAIN_SEPARATOR, "/"));
    }
    Ok(())
}

fn utf8_file(path: &str, bytes: Vec<u8>) -> Result<String, ManagerError> {
    String::from_utf8(bytes).map_err(|_| {
        ManagerError::InvalidProject(format!("legacy path `{path}` is not valid UTF-8"))
    })
}

fn validate_unique_values(values: &[String], label: &str) -> Result<(), ManagerError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.is_empty() || !unique.insert(value.as_str()) {
            return Err(ManagerError::InvalidProject(format!(
                "duplicate or empty {label} `{value}`"
            )));
        }
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_schema_one_baselines_are_immutable_and_self_consistent()
    -> Result<(), ManagerError> {
        let expected = [
            "a441c4dabe35c15925e6a02e1ba876133921180c50253e0a931f46e6f33ab6f9",
            "a0a1b7d8a3618e3bd2f3ec4f469f1e72b18393625381018007123dd9fc92ddc0",
            "9d631c505af602b6a9ce31aefd19ff782f9f6d60db80d42326f7744c7b6ebf24",
        ];
        for (recipe, expected_digest) in FROZEN_RECIPES.iter().zip(expected) {
            assert_eq!(sha256_hex(recipe.baseline.as_bytes()), expected_digest);
            let baseline = parse_frozen_baseline(recipe)?;
            assert_eq!(baseline.files.len(), 391);
            assert!(
                baseline
                    .module_versions
                    .values()
                    .all(|version| version == recipe.module_version)
            );
        }
        Ok(())
    }

    #[test]
    fn private_schema_one_parser_denies_unknown_fields() {
        let Some(state) = test_legacy_files().remove(PROJECT_STATE_PATH) else {
            panic!("test state must be present");
        };
        let source = format!("unknown = true\n{state}");
        let Err(error) = decode_legacy_state(&source) else {
            panic!("unknown fields must fail closed");
        };
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn legacy_provider_assertions_must_match_the_frozen_state() {
        let Some(state) = test_legacy_files().remove(PROJECT_STATE_PATH) else {
            panic!("test state must be present");
        };
        let source = state.replace(
            "providers = []\n",
            "providers = [{ slot = \"unexpected-slot\", module = \"core\" }]\n",
        );
        let Ok(legacy) = decode_legacy_state(&source) else {
            panic!("modified state must be structurally valid");
        };
        let baseline = test_frozen_baseline();
        let Err(error) = validate_legacy_state(&legacy, &TEST_FROZEN_RECIPE, &baseline) else {
            panic!("provider relabelling must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("provider assertions do not match")
        );
    }
}
