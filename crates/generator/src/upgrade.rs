use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use crate::{
    KIT_VERSION,
    manager::{
        ManagementPlan, ManagerError, PlanOperation, ProjectSnapshot, doctor, finish_upgrade_plan,
        preserves_historical_path, render_derived,
    },
    modules::ModuleCatalog,
    region::{ManagedRegion, parse_managed_regions, reconcile_managed_region},
    state::{
        ManagedRegionRecord, OwnershipKind, OwnershipRecord, PROJECT_STATE_PATH, ProjectState,
        sha256_hex,
    },
};

const PRIOR_VERSION: &str = "0.0.0";
const PRIOR_CARGO: &str = include_str!("../tests/fixtures/prior-0.0.0/Cargo.toml");
const PRIOR_DOCKERFILE: &str = include_str!("../tests/fixtures/prior-0.0.0/Dockerfile");

/// One supported, direct service-kit upgrade transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeRecipe {
    /// Exact source kit version.
    pub from: &'static str,
    /// Exact target kit version.
    pub to: &'static str,
}

/// Versioned upgrade transitions compiled into this generator release.
pub const UPGRADE_RECIPES: &[UpgradeRecipe] = &[UpgradeRecipe {
    from: PRIOR_VERSION,
    to: KIT_VERSION,
}];

/// Produces a pure, deterministic upgrade plan from a supplied project snapshot.
///
/// # Errors
///
/// Returns [`ManagerError`] for unsupported versions, stale state or baselines,
/// ownership or marker drift, and dependency override conflicts.
pub fn plan_upgrade(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    target_version: &str,
) -> Result<ManagementPlan, ManagerError> {
    validate_target(catalog, target_version)?;
    if snapshot.state.kit_version == target_version {
        let report = doctor(catalog, snapshot);
        if !report.healthy {
            return Err(ManagerError::Preflight(report.diagnostics));
        }
        return finish_upgrade_plan(target_version, Vec::new(), Vec::new());
    }
    let recipe = UPGRADE_RECIPES
        .iter()
        .find(|recipe| snapshot.state.kit_version == recipe.from && recipe.to == target_version)
        .ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "unsupported service-kit upgrade {} -> {target_version}",
                snapshot.state.kit_version
            ))
        })?;
    validate_source_state(catalog, snapshot, recipe)?;

    let source_baselines = prior_baselines(snapshot);
    validate_dependency_overrides(snapshot, &source_baselines)?;
    let mut operations = Vec::new();
    let mut preserved = preserved_history(catalog, &snapshot.state);
    plan_owned_files(
        catalog,
        snapshot,
        &source_baselines,
        recipe,
        &mut operations,
        &mut preserved,
    )?;
    let mut next_state = upgraded_state(catalog, &snapshot.state, target_version)?;
    plan_lockfile(
        snapshot,
        recipe,
        target_version,
        &mut next_state,
        &mut operations,
    )?;
    append_upgraded_state(snapshot, &next_state, &mut operations)?;
    finish_upgrade_plan(target_version, operations, preserved.into_iter().collect())
}

fn validate_target(catalog: &ModuleCatalog, target: &str) -> Result<(), ManagerError> {
    if target != KIT_VERSION || target != catalog.bundle_version.as_str() {
        return Err(ManagerError::InvalidProject(format!(
            "unsupported service-kit upgrade target `{target}`; this generator supports `{KIT_VERSION}`"
        )));
    }
    Ok(())
}

fn validate_source_state(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    recipe: &UpgradeRecipe,
) -> Result<(), ManagerError> {
    snapshot.state.validate()?;
    catalog.validate()?;
    if snapshot.state.profile.version != recipe.from {
        return Err(ManagerError::InvalidProject(format!(
            "stale profile state: expected version {}, found {}",
            recipe.from, snapshot.state.profile.version
        )));
    }
    for module in &snapshot.state.modules {
        if module.version != recipe.from {
            return Err(ManagerError::InvalidProject(format!(
                "stale module state for `{}`: expected version {}, found {}",
                module.id, recipe.from, module.version
            )));
        }
    }
    let selected = snapshot
        .state
        .modules
        .iter()
        .map(|module| module.id.clone())
        .collect();
    catalog.validate_selection(&selected)?;
    if snapshot.state.ownership_of(PROJECT_STATE_PATH) != Some(OwnershipKind::KitOwned) {
        return Err(ManagerError::InvalidProject(
            "project state must remain kit-owned during upgrade".to_owned(),
        ));
    }
    Ok(())
}

fn prior_baselines(snapshot: &ProjectSnapshot) -> BTreeMap<String, String> {
    let mut baselines = snapshot.kit_sources.clone();
    baselines.insert("Cargo.toml".to_owned(), PRIOR_CARGO.to_owned());
    baselines.insert(
        "ops/Dockerfile".to_owned(),
        PRIOR_DOCKERFILE.replace("{{project-name}}", &snapshot.state.service),
    );
    baselines
}

fn validate_dependency_overrides(
    snapshot: &ProjectSnapshot,
    source_baselines: &BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    let Some(record) = snapshot
        .state
        .managed_region("Cargo.toml", "workspace-dependencies")
    else {
        return Err(ManagerError::InvalidProject(
            "upgrade source is missing the workspace-dependencies ownership record".to_owned(),
        ));
    };
    let current = snapshot.files.get("Cargo.toml").ok_or_else(|| {
        ManagerError::InvalidProject("upgrade source is missing Cargo.toml".to_owned())
    })?;
    let regions = parse_managed_regions(current)?;
    let region = required_region(&regions, record, "Cargo.toml")?;
    let overrides = dependency_names(region.content, "managed workspace dependencies")?;
    let target = snapshot.kit_sources.get("Cargo.toml").ok_or_else(|| {
        ManagerError::InvalidProject("target Cargo.toml baseline is unavailable".to_owned())
    })?;
    let target_names = target_dependency_names(target)?;
    if let Some(conflict) = overrides.intersection(&target_names).next() {
        return Err(ManagerError::InvalidProject(format!(
            "dependency override conflict for `{conflict}`; target kit owns this workspace dependency"
        )));
    }
    let source = source_baselines.get("Cargo.toml").ok_or_else(|| {
        ManagerError::InvalidProject("source Cargo.toml baseline is unavailable".to_owned())
    })?;
    rebase_managed_file(current, source, target, &snapshot.state, "Cargo.toml")?;
    Ok(())
}

fn dependency_names(content: &str, label: &str) -> Result<BTreeSet<String>, ManagerError> {
    let source = format!("[workspace.dependencies]\n{content}");
    let value: toml::Value = toml::from_str(&source)
        .map_err(|error| ManagerError::InvalidProject(format!("cannot parse {label}: {error}")))?;
    Ok(value
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .map(|dependencies| dependencies.keys().cloned().collect())
        .unwrap_or_default())
}

fn target_dependency_names(source: &str) -> Result<BTreeSet<String>, ManagerError> {
    let value: toml::Value = toml::from_str(source).map_err(|error| {
        ManagerError::InvalidProject(format!("cannot parse target Cargo.toml: {error}"))
    })?;
    Ok(value
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .map(|dependencies| dependencies.keys().cloned().collect())
        .unwrap_or_default())
}

fn plan_owned_files(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    source_baselines: &BTreeMap<String, String>,
    recipe: &UpgradeRecipe,
    operations: &mut Vec<PlanOperation>,
    preserved: &mut BTreeSet<String>,
) -> Result<(), ManagerError> {
    let selected: BTreeSet<String> = snapshot
        .state
        .modules
        .iter()
        .map(|module| module.id.clone())
        .collect();
    for ownership in &snapshot.state.ownership {
        if ownership.path == PROJECT_STATE_PATH || ownership.path == "Cargo.lock" {
            continue;
        }
        let current = snapshot.files.get(&ownership.path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "owned upgrade source is missing: `{}`",
                ownership.path
            ))
        })?;
        match ownership.kind {
            OwnershipKind::ApplicationOwned => {}
            OwnershipKind::KitOwned if preserves_historical_path(&ownership.path) => {
                preserved.insert(ownership.path.clone());
            }
            OwnershipKind::KitOwned => {
                plan_kit_owned_upgrade(snapshot, source_baselines, ownership, current, operations)?;
            }
            OwnershipKind::Derived => {
                plan_derived_upgrade(catalog, &selected, ownership, current, recipe, operations)?;
            }
        }
    }
    Ok(())
}

fn plan_kit_owned_upgrade(
    snapshot: &ProjectSnapshot,
    source_baselines: &BTreeMap<String, String>,
    ownership: &OwnershipRecord,
    current: &str,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let source = source_baselines.get(&ownership.path).ok_or_else(|| {
        ManagerError::InvalidProject(format!(
            "unsupported source baseline for kit-owned file `{}`",
            ownership.path
        ))
    })?;
    let target = snapshot.kit_sources.get(&ownership.path).ok_or_else(|| {
        ManagerError::InvalidProject(format!(
            "target baseline is unavailable for kit-owned file `{}`",
            ownership.path
        ))
    })?;
    let content = if snapshot
        .state
        .managed_regions
        .iter()
        .any(|record| record.path == ownership.path)
    {
        rebase_managed_file(current, source, target, &snapshot.state, &ownership.path)?
    } else {
        if current != source {
            return Err(ManagerError::InvalidProject(format!(
                "kit-owned source baseline drift in `{}`",
                ownership.path
            )));
        }
        target.clone()
    };
    if content != current {
        operations.push(PlanOperation::ReplaceKitFile {
            path: ownership.path.clone(),
            expected_hash: sha256_hex(current.as_bytes()),
            content_hash: sha256_hex(content.as_bytes()),
            content,
        });
    }
    Ok(())
}

fn plan_derived_upgrade(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    ownership: &OwnershipRecord,
    current: &str,
    recipe: &UpgradeRecipe,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let target = render_derived(&ownership.path, catalog, selected)?;
    let source = target.replace(recipe.to, recipe.from);
    if current != source {
        return Err(ManagerError::InvalidProject(format!(
            "derived source baseline drift in `{}`",
            ownership.path
        )));
    }
    if current != target {
        operations.push(PlanOperation::RegenerateDerived {
            path: ownership.path.clone(),
            expected_hash: Some(sha256_hex(current.as_bytes())),
            content_hash: sha256_hex(target.as_bytes()),
            content: target,
        });
    }
    Ok(())
}

fn rebase_managed_file(
    current: &str,
    source: &str,
    target: &str,
    state: &ProjectState,
    path: &str,
) -> Result<String, ManagerError> {
    let current_regions = parse_managed_regions(current)?;
    let source_regions = parse_managed_regions(source)?;
    let records: Vec<&ManagedRegionRecord> = state
        .managed_regions
        .iter()
        .filter(|record| record.path == path)
        .collect();
    let mut normalized = current.to_owned();
    let mut preserved = Vec::with_capacity(records.len());
    for record in &records {
        let current_region = required_region(&current_regions, record, path)?;
        let source_region = required_region(&source_regions, record, path)?;
        preserved.push((record.id.as_str(), current_region.content.to_owned()));
        normalized = reconcile_managed_region(&normalized, record, source_region.content)?;
    }
    if normalized != source {
        return Err(ManagerError::InvalidProject(format!(
            "kit-owned source baseline drift outside managed regions in `{path}`"
        )));
    }

    let mut rebased = target.to_owned();
    for (id, content) in preserved {
        let target_regions = parse_managed_regions(&rebased)?;
        let target_region = target_regions
            .iter()
            .find(|region| region.id == id)
            .ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "target baseline `{path}` is missing managed region `{id}`"
                ))
            })?;
        let target_record = ManagedRegionRecord {
            id: id.to_owned(),
            path: path.to_owned(),
            marker_version: target_region.marker_version,
            content_hash: target_region.content_hash.to_owned(),
        };
        rebased = reconcile_managed_region(&rebased, &target_record, &content)?;
    }
    Ok(rebased)
}

fn required_region<'a>(
    regions: &'a [ManagedRegion<'a>],
    record: &ManagedRegionRecord,
    path: &str,
) -> Result<&'a ManagedRegion<'a>, ManagerError> {
    regions
        .iter()
        .find(|region| region.id == record.id)
        .ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "managed region `{}` is missing from `{path}`",
                record.id
            ))
        })
}

fn upgraded_state(
    catalog: &ModuleCatalog,
    state: &ProjectState,
    target: &str,
) -> Result<ProjectState, ManagerError> {
    let mut upgraded = state.clone();
    target.clone_into(&mut upgraded.kit_version);
    target.clone_into(&mut upgraded.profile.version);
    for module in &mut upgraded.modules {
        let definition = catalog.module(&module.id).ok_or_else(|| {
            ManagerError::InvalidProject(format!("unknown module `{}` in upgrade state", module.id))
        })?;
        module.version.clone_from(&definition.version);
    }
    upgraded.modules.sort();
    upgraded.profile.additions.sort();
    upgraded.profile.removals.sort();
    upgraded.ownership.sort();
    upgraded.managed_regions.sort();
    Ok(upgraded)
}

fn plan_lockfile(
    snapshot: &ProjectSnapshot,
    recipe: &UpgradeRecipe,
    target: &str,
    state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let Some(current) = snapshot.files.get("Cargo.lock") else {
        return Ok(());
    };
    match snapshot.state.ownership_of("Cargo.lock") {
        Some(OwnershipKind::ApplicationOwned | OwnershipKind::KitOwned) => {
            return Err(ManagerError::InvalidProject(
                "refusing to upgrade non-derived Cargo.lock".to_owned(),
            ));
        }
        Some(OwnershipKind::Derived) => {}
        None => state.ownership.push(OwnershipRecord {
            path: "Cargo.lock".to_owned(),
            kind: OwnershipKind::Derived,
        }),
    }
    let upgraded = upgrade_lockfile(current, &state.service, recipe.from, target)?;
    if upgraded != *current {
        operations.push(PlanOperation::WriteLock {
            path: "Cargo.lock".to_owned(),
            expected_hash: sha256_hex(current.as_bytes()),
            content_hash: sha256_hex(upgraded.as_bytes()),
            content: upgraded,
        });
    }
    state.ownership.sort();
    Ok(())
}

fn upgrade_lockfile(
    source: &str,
    service: &str,
    from: &str,
    to: &str,
) -> Result<String, ManagerError> {
    let mut output = String::with_capacity(source.len());
    let mut package_name: Option<&str> = None;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            package_name = None;
        } else if let Some(value) = quoted_assignment(trimmed, "name") {
            package_name = Some(value);
        }
        if let (Some(version), Some(name)) = (quoted_assignment(trimmed, "version"), package_name)
            && (name == service || name.starts_with("omnius-"))
        {
            if version != from {
                return Err(ManagerError::InvalidProject(format!(
                    "stale Cargo.lock package `{name}` version {version}; expected {from}"
                )));
            }
            let newline = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            write!(&mut output, "version = \"{to}\"{newline}").map_err(|_| {
                ManagerError::InvalidProject("cannot render upgraded Cargo.lock".to_owned())
            })?;
        } else {
            output.push_str(line);
        }
    }
    Ok(output)
}

fn quoted_assignment<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let value = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    value.strip_prefix('"')?.strip_suffix('"')
}

fn append_upgraded_state(
    snapshot: &ProjectSnapshot,
    state: &ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let content = state.to_toml()?;
    let current = snapshot.files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject(format!("missing required `{PROJECT_STATE_PATH}`"))
    })?;
    operations.push(PlanOperation::WriteState {
        path: PROJECT_STATE_PATH.to_owned(),
        expected_hash: sha256_hex(current.as_bytes()),
        content_hash: sha256_hex(content.as_bytes()),
        content,
    });
    Ok(())
}

fn preserved_history(catalog: &ModuleCatalog, state: &ProjectState) -> BTreeSet<String> {
    let mut preserved: BTreeSet<String> = state
        .ownership
        .iter()
        .filter(|record| preserves_historical_path(&record.path))
        .map(|record| record.path.clone())
        .collect();
    for selected in &state.modules {
        if let Some(module) = catalog.module(&selected.id) {
            preserved.extend(module.persistence.iter().cloned());
        }
    }
    preserved
}
