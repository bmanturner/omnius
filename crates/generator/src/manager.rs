use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    modules::{CatalogError, ModuleCatalog, ModuleDefinition},
    region::{RegionError, parse_managed_regions, reconcile_managed_region},
    render::{RenderError, render_kit_baselines},
    state::{
        MANAGED_MARKER_VERSION, ManagedRegionRecord, OwnershipKind, OwnershipRecord,
        PROJECT_STATE_PATH, ProjectState, SelectedModule, SelectedProvider, StateError, sha256_hex,
        validate_relative_path,
    },
};

const PLAN_SCHEMA_VERSION: u32 = 1;
const BACKUP_SCHEMA_VERSION: u32 = 1;

/// Filesystem-free inputs to deterministic module planning.
#[derive(Clone, Debug)]
pub struct ProjectSnapshot {
    /// Strict project state.
    pub state: ProjectState,
    /// Exact UTF-8 contents of known project paths. Missing keys mean absent files.
    pub files: BTreeMap<String, String>,
    /// Exact approved kit baseline for catalog kit-owned paths.
    pub kit_sources: BTreeMap<String, String>,
    /// Root workspace dependency definitions available to installed module crates.
    pub workspace_dependencies: BTreeMap<String, String>,
}

/// Kind of deterministic management plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanAction {
    /// Add a requested module and transitive dependencies.
    Add,
    /// Remove a module after reverse-dependency checks.
    Remove,
    /// Reconcile selected state without changing selection.
    Diff,
    /// Upgrade a generated project through a versioned recipe.
    Upgrade,
}

/// One deterministic filesystem operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum PlanOperation {
    /// Create a previously absent kit-owned file.
    CreateFile {
        /// Project-relative target path.
        path: String,
        /// Hash of the new content.
        content_hash: String,
        /// Exact new UTF-8 content.
        content: String,
    },
    /// Replace a kit-owned file after exact source-baseline validation.
    ReplaceKitFile {
        /// Project-relative target path.
        path: String,
        /// Expected prior baseline hash.
        expected_hash: String,
        /// Hash of target baseline content.
        content_hash: String,
        /// Exact target baseline content.
        content: String,
    },
    /// Replace a file composed from approved managed-region reconciliations.
    ReconcileRegions {
        /// Project-relative target path.
        path: String,
        /// Expected whole-file hash before mutation.
        expected_hash: String,
        /// Hash after reconciliation.
        content_hash: String,
        /// Stable region IDs reconciled in this file.
        region_ids: Vec<String>,
        /// Exact whole-file content after preserving outside bytes.
        content: String,
    },
    /// Deterministically regenerate a derived file.
    RegenerateDerived {
        /// Project-relative target path.
        path: String,
        /// Expected hash, or `None` when creating the file.
        expected_hash: Option<String>,
        /// Hash of generated content.
        content_hash: String,
        /// Exact generated content.
        content: String,
    },
    /// Remove a kit-owned file whose current bytes match the approved baseline.
    RemoveFile {
        /// Project-relative target path.
        path: String,
        /// Expected approved baseline hash.
        expected_hash: String,
    },
    /// Update a generated Cargo lockfile after all source files.
    WriteLock {
        /// Always `Cargo.lock`.
        path: String,
        /// Expected prior lockfile hash.
        expected_hash: String,
        /// Hash of the upgraded lockfile.
        content_hash: String,
        /// Exact upgraded lockfile bytes.
        content: String,
    },
    /// Commit project state after every other operation succeeds.
    WriteState {
        /// Always `.omnius/service.toml`.
        path: String,
        /// Expected prior-state hash.
        expected_hash: String,
        /// Hash of the committed state.
        content_hash: String,
        /// Exact new TOML state.
        content: String,
    },
}

impl PlanOperation {
    fn path(&self) -> &str {
        match self {
            Self::CreateFile { path, .. }
            | Self::ReplaceKitFile { path, .. }
            | Self::ReconcileRegions { path, .. }
            | Self::RegenerateDerived { path, .. }
            | Self::RemoveFile { path, .. }
            | Self::WriteLock { path, .. }
            | Self::WriteState { path, .. } => path,
        }
    }

    fn content(&self) -> Option<&str> {
        match self {
            Self::CreateFile { content, .. }
            | Self::ReplaceKitFile { content, .. }
            | Self::ReconcileRegions { content, .. }
            | Self::RegenerateDerived { content, .. }
            | Self::WriteLock { content, .. }
            | Self::WriteState { content, .. } => Some(content),
            Self::RemoveFile { .. } => None,
        }
    }

    fn expected_hash(&self) -> Option<&str> {
        match self {
            Self::CreateFile { .. } => None,
            Self::ReplaceKitFile { expected_hash, .. }
            | Self::ReconcileRegions { expected_hash, .. }
            | Self::RemoveFile { expected_hash, .. }
            | Self::WriteLock { expected_hash, .. }
            | Self::WriteState { expected_hash, .. } => Some(expected_hash),
            Self::RegenerateDerived { expected_hash, .. } => expected_hash.as_deref(),
        }
    }

    fn order(&self) -> u8 {
        match self {
            Self::CreateFile { .. } => 0,
            Self::ReplaceKitFile { .. } | Self::ReconcileRegions { .. } => 1,
            Self::RegenerateDerived { .. } => 2,
            Self::RemoveFile { .. } => 3,
            Self::WriteLock { .. } => 4,
            Self::WriteState { .. } => 5,
        }
    }
}

/// Reviewable deterministic plan used for dry-run, JSON, and safe application.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManagementPlan {
    /// Machine output schema.
    pub schema_version: u32,
    /// SHA-256 identity of every plan input and operation.
    pub plan_id: String,
    /// Requested operation.
    pub action: PlanAction,
    /// Explicit requested module for add/remove.
    pub requested_module: Option<String>,
    /// Explicit upgrade target for upgrade plans.
    pub target_version: Option<String>,
    /// Newly selected modules, including transitive prerequisites.
    pub added_modules: Vec<String>,
    /// Modules removed from selection.
    pub removed_modules: Vec<String>,
    /// Ordered filesystem changes; project state is always last.
    pub operations: Vec<PlanOperation>,
    /// Migration or persistence paths explicitly retained on removal.
    pub preserved_paths: Vec<String>,
}

impl ManagementPlan {
    /// Whether applying the plan would change no project file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

/// One deterministic doctor finding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Diagnostic {
    /// Stable machine-readable category.
    pub code: String,
    /// Related project path, when applicable.
    pub path: Option<String>,
    /// Actionable human-readable explanation.
    pub message: String,
}

/// Nonmutating health report for state, catalog, ownership, and generated files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorReport {
    /// Machine output schema.
    pub schema_version: u32,
    /// True only when no findings exist.
    pub healthy: bool,
    /// Sorted deterministic findings.
    pub diagnostics: Vec<Diagnostic>,
}

/// Result of a successfully applied nonempty plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplyOutcome {
    /// Applied deterministic plan identity.
    pub plan_id: String,
    /// Project-relative deterministic backup artifact.
    pub backup_artifact: String,
    /// Number of project files changed, including state.
    pub changed_files: usize,
}

/// Planning, validation, ownership, or filesystem failure.
#[derive(Debug)]
pub enum ManagerError {
    /// Module catalog error.
    Catalog(CatalogError),
    /// Strict project state error.
    State(StateError),
    /// Managed marker error.
    Region(RegionError),
    /// Base-template rendering error while reconstructing approved baselines.
    Render(RenderError),
    /// Project preflight findings blocked planning or application.
    Preflight(Vec<Diagnostic>),
    /// A plan no longer matches current project bytes.
    StalePlan(String),
    /// A project path or source was unavailable or unsafe.
    InvalidProject(String),
    /// A filesystem operation failed.
    Filesystem {
        /// Path whose filesystem operation failed.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Deterministic JSON backup encoding failed.
    BackupEncoding(serde_json::Error),
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => write!(formatter, "module catalog error: {error}"),
            Self::State(error) => write!(formatter, "project state error: {error}"),
            Self::Region(error) => write!(formatter, "managed region error: {error}"),
            Self::Render(error) => write!(formatter, "base template error: {error}"),
            Self::Preflight(diagnostics) => {
                formatter.write_str("project preflight failed")?;
                for diagnostic in diagnostics {
                    write!(formatter, "; {}: {}", diagnostic.code, diagnostic.message)?;
                }
                Ok(())
            }
            Self::StalePlan(message) | Self::InvalidProject(message) => {
                formatter.write_str(message)
            }
            Self::Filesystem { path, source } => {
                write!(
                    formatter,
                    "filesystem operation failed for {}: {source}",
                    path.display()
                )
            }
            Self::BackupEncoding(error) => {
                write!(formatter, "cannot encode backup artifact: {error}")
            }
        }
    }
}

impl Error for ManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Catalog(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Region(error) => Some(error),
            Self::Render(error) => Some(error),
            Self::Filesystem { source, .. } => Some(source),
            Self::BackupEncoding(error) => Some(error),
            Self::Preflight(_) | Self::StalePlan(_) | Self::InvalidProject(_) => None,
        }
    }
}

impl From<CatalogError> for ManagerError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

impl From<StateError> for ManagerError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<RegionError> for ManagerError {
    fn from(error: RegionError) -> Self {
        Self::Region(error)
    }
}

impl From<RenderError> for ManagerError {
    fn from(error: RenderError) -> Self {
        Self::Render(error)
    }
}

/// Filesystem boundary around the pure catalog planner.
pub struct ProjectManager<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) kit_root: &'a Path,
    pub(crate) catalog: &'a ModuleCatalog,
}

impl<'a> ProjectManager<'a> {
    /// Creates a manager for one project and the kit source tree containing
    /// approved catalog-owned baselines.
    #[must_use]
    pub fn new(project_root: &'a Path, kit_root: &'a Path, catalog: &'a ModuleCatalog) -> Self {
        Self {
            project_root,
            kit_root,
            catalog,
        }
    }

    /// Plans a module add without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for invalid state, corrupt ownership, conflicts,
    /// missing sources, or unsafe project paths.
    pub fn plan_add(&self, module: &str) -> Result<ManagementPlan, ManagerError> {
        let snapshot = self.load_snapshot()?;
        plan_add(self.catalog, &snapshot, module)
    }

    /// Plans a module removal without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for reverse dependents, drift, corruption, or
    /// any other preflight error.
    pub fn plan_remove(&self, module: &str) -> Result<ManagementPlan, ManagerError> {
        let snapshot = self.load_snapshot()?;
        plan_remove(self.catalog, &snapshot, module)
    }

    /// Produces the deterministic reconciliation diff without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] when project state cannot be safely inspected.
    pub fn diff(&self) -> Result<ManagementPlan, ManagerError> {
        let snapshot = self.load_snapshot()?;
        plan_diff(self.catalog, &snapshot)
    }

    /// Plans a versioned project upgrade without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for unsupported versions, stale baselines,
    /// ownership drift, or dependency override conflicts.
    pub fn plan_upgrade(&self, target_version: &str) -> Result<ManagementPlan, ManagerError> {
        let snapshot = self.load_snapshot()?;
        crate::upgrade::plan_upgrade(self.catalog, &snapshot, target_version)
    }

    /// Diagnoses state, dependency closure, catalog versions, owned files, and
    /// managed markers without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] only when the project cannot be read or state
    /// cannot be decoded. Health findings are returned in the report.
    pub fn doctor(&self) -> Result<DoctorReport, ManagerError> {
        let snapshot = self.load_snapshot()?;
        Ok(doctor(self.catalog, &snapshot))
    }

    /// Applies a previously reviewed add/remove/upgrade plan after recalculating
    /// every precondition, writes a deterministic backup, rolls back on write
    /// errors, and commits lockfile and state last.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] without target mutation for every preflight or
    /// stale-plan failure. Filesystem failures attempt byte-exact rollback.
    pub fn apply(&self, plan: &ManagementPlan) -> Result<ApplyOutcome, ManagerError> {
        if plan.action == PlanAction::Diff {
            return Err(ManagerError::InvalidProject(
                "diff plans are nonmutating and cannot be applied".to_owned(),
            ));
        }
        let current = match (plan.action, plan.requested_module.as_deref()) {
            (PlanAction::Add, Some(module)) => self.plan_add(module)?,
            (PlanAction::Remove, Some(module)) => self.plan_remove(module)?,
            (PlanAction::Upgrade, None) => {
                let target = plan.target_version.as_deref().ok_or_else(|| {
                    ManagerError::InvalidProject(
                        "upgrade plan is missing its target version".to_owned(),
                    )
                })?;
                self.plan_upgrade(target)?
            }
            _ => {
                return Err(ManagerError::InvalidProject(
                    "management plan arguments do not match its action".to_owned(),
                ));
            }
        };
        if current.plan_id != plan.plan_id || current != *plan {
            return Err(ManagerError::StalePlan(format!(
                "refusing stale plan {}; current deterministic plan is {}",
                plan.plan_id, current.plan_id
            )));
        }
        if plan.is_empty() {
            return Ok(ApplyOutcome {
                plan_id: plan.plan_id.clone(),
                backup_artifact: String::new(),
                changed_files: 0,
            });
        }

        let backup_path = format!(".omnius/backups/{}/backup.json", plan.plan_id);
        ensure_safe_project_path(self.project_root, &backup_path)?;
        let backup_entries = self.preflight_operations(plan)?;
        let artifact = BackupArtifact {
            schema_version: BACKUP_SCHEMA_VERSION,
            plan_id: plan.plan_id.clone(),
            entries: backup_entries
                .iter()
                .map(|(path, previous)| BackupEntry {
                    path: path.clone(),
                    previous: previous.clone(),
                })
                .collect(),
        };
        let mut backup_contents =
            serde_json::to_string_pretty(&artifact).map_err(ManagerError::BackupEncoding)?;
        backup_contents.push('\n');
        let absolute_backup = self.project_root.join(&backup_path);
        if absolute_backup.exists() {
            return Err(ManagerError::InvalidProject(format!(
                "deterministic backup artifact already exists: {backup_path}"
            )));
        }
        atomic_write(&absolute_backup, &backup_contents, &plan.plan_id)?;

        let mut applied = Vec::new();
        for operation in &plan.operations {
            let result = self.apply_operation(operation, &plan.plan_id);
            if let Err(error) = result {
                if let Err(rollback) = self.rollback(&applied, &backup_entries, &plan.plan_id) {
                    return Err(ManagerError::InvalidProject(format!(
                        "apply failed: {error}; rollback also failed: {rollback}"
                    )));
                }
                return Err(error);
            }
            applied.push(operation.path().to_owned());
        }
        Ok(ApplyOutcome {
            plan_id: plan.plan_id.clone(),
            backup_artifact: backup_path,
            changed_files: plan.operations.len(),
        })
    }

    pub(crate) fn load_snapshot(&self) -> Result<ProjectSnapshot, ManagerError> {
        ensure_safe_project_path(self.project_root, PROJECT_STATE_PATH)?;
        let state_path = self.project_root.join(PROJECT_STATE_PATH);
        let state_source = read_required_file(&state_path)?;
        let state = ProjectState::parse(&state_source)?;
        let mut kit_sources = render_kit_baselines(&state.service, &state.profile.id)?;
        collect_catalog_kit_sources(self.kit_root, self.catalog, &mut kit_sources)?;
        let workspace_dependencies = load_kit_workspace_dependencies(self.kit_root)?;

        let mut paths = BTreeSet::new();
        paths.insert(PROJECT_STATE_PATH.to_owned());
        paths.insert("Cargo.lock".to_owned());
        paths.extend(state.ownership.iter().map(|record| record.path.clone()));
        paths.extend(
            state
                .managed_regions
                .iter()
                .map(|region| region.path.clone()),
        );
        paths.extend(kit_sources.keys().cloned());
        for module in &self.catalog.modules {
            paths.extend(
                module
                    .generator_ownership
                    .derived
                    .iter()
                    .filter(|path| MANAGER_DERIVED_PATHS.contains(&path.as_str()))
                    .cloned(),
            );
            for reference in &module.generator_ownership.managed_regions {
                let Some((pattern, _)) = reference.rsplit_once('#') else {
                    continue;
                };
                if pattern.contains('*') {
                    paths.extend(expand_pattern(self.project_root, pattern)?);
                } else {
                    paths.insert(pattern.to_owned());
                }
            }
        }

        let mut files = BTreeMap::new();
        for path in &paths {
            validate_relative_path(path)?;
            ensure_safe_project_path(self.project_root, path)?;
            let absolute = self.project_root.join(path);
            if let Some(contents) = read_optional_file(&absolute)? {
                files.insert(path.clone(), contents);
            }
        }
        Ok(ProjectSnapshot {
            state,
            files,
            kit_sources,
            workspace_dependencies,
        })
    }

    fn preflight_operations(
        &self,
        plan: &ManagementPlan,
    ) -> Result<BTreeMap<String, Option<String>>, ManagerError> {
        let mut originals = BTreeMap::new();
        for operation in &plan.operations {
            let path = operation.path();
            validate_relative_path(path)?;
            ensure_safe_project_path(self.project_root, path)?;
            let current = read_optional_file(&self.project_root.join(path))?;
            match (operation.expected_hash(), current.as_deref()) {
                (None, None) => {}
                (None, Some(_)) => {
                    return Err(ManagerError::StalePlan(format!(
                        "plan expected `{path}` to be absent"
                    )));
                }
                (Some(expected), Some(contents)) if sha256_hex(contents.as_bytes()) == expected => {
                }
                (Some(expected), Some(contents)) => {
                    return Err(ManagerError::StalePlan(format!(
                        "plan expected `{path}` hash {expected}, found {}",
                        sha256_hex(contents.as_bytes())
                    )));
                }
                (Some(_), None) => {
                    return Err(ManagerError::StalePlan(format!(
                        "plan expected `{path}` to exist"
                    )));
                }
            }
            originals.insert(path.to_owned(), current);
        }
        Ok(originals)
    }

    fn apply_operation(
        &self,
        operation: &PlanOperation,
        plan_id: &str,
    ) -> Result<(), ManagerError> {
        ensure_safe_project_path(self.project_root, operation.path())?;
        let absolute = self.project_root.join(operation.path());
        if let Some(content) = operation.content() {
            atomic_write(&absolute, content, plan_id)
        } else {
            fs::remove_file(&absolute).map_err(|source| ManagerError::Filesystem {
                path: absolute.clone(),
                source,
            })?;
            remove_empty_ancestors(&absolute, self.project_root)?;
            Ok(())
        }
    }

    fn rollback(
        &self,
        applied: &[String],
        originals: &BTreeMap<String, Option<String>>,
        plan_id: &str,
    ) -> Result<(), ManagerError> {
        for path in applied.iter().rev() {
            let absolute = self.project_root.join(path);
            match originals.get(path).and_then(Option::as_deref) {
                Some(contents) => atomic_write(&absolute, contents, plan_id)?,
                None => match fs::remove_file(&absolute) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(ManagerError::Filesystem {
                            path: absolute,
                            source,
                        });
                    }
                },
            }
        }
        Ok(())
    }
}

pub(crate) fn compose_initial_profile(
    kit_root: &Path,
    catalog: &ModuleCatalog,
    state: ProjectState,
    mut files: BTreeMap<String, String>,
    mut kit_sources: BTreeMap<String, String>,
) -> Result<(ProjectState, BTreeMap<String, String>), ManagerError> {
    collect_catalog_kit_sources(kit_root, catalog, &mut kit_sources)?;
    let workspace_dependencies = load_kit_workspace_dependencies(kit_root)?;
    let snapshot = ProjectSnapshot {
        state: state.clone(),
        files: files.clone(),
        kit_sources,
        workspace_dependencies,
    };
    let selected = selected_ids(&state);
    catalog.validate_selection(&selected)?;
    let selection = SelectionChange {
        before: selected.clone(),
        after: selected.clone(),
        added: selected.iter().cloned().collect(),
        removed: Vec::new(),
    };
    let mut next_state = state;
    let (mut operations, _) =
        build_plan_operations(catalog, &snapshot, &selection, &mut next_state)?;
    append_state_operation(catalog, &snapshot, &mut next_state, &mut operations)?;
    operations.sort_by(|left, right| {
        left.order()
            .cmp(&right.order())
            .then_with(|| left.path().cmp(right.path()))
    });
    for operation in operations {
        match operation {
            PlanOperation::RemoveFile { path, .. } => {
                files.remove(&path);
            }
            PlanOperation::CreateFile { path, content, .. }
            | PlanOperation::ReplaceKitFile { path, content, .. }
            | PlanOperation::ReconcileRegions { path, content, .. }
            | PlanOperation::RegenerateDerived { path, content, .. }
            | PlanOperation::WriteLock { path, content, .. }
            | PlanOperation::WriteState { path, content, .. } => {
                files.insert(path, content);
            }
        }
    }
    let state_source = files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject("initial profile composition removed project state".to_owned())
    })?;
    let final_state = ProjectState::parse(state_source)?;
    Ok((final_state, files))
}

/// Pure add planning from a supplied snapshot.
///
/// # Errors
///
/// Returns [`ManagerError`] for any catalog, state, ownership, or marker error.
pub fn plan_add(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    requested: &str,
) -> Result<ManagementPlan, ManagerError> {
    plan(catalog, snapshot, PlanAction::Add, Some(requested))
}

/// Pure remove planning from a supplied snapshot.
///
/// # Errors
///
/// Returns [`ManagerError`] for reverse dependents or any unsafe preflight.
pub fn plan_remove(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    requested: &str,
) -> Result<ManagementPlan, ManagerError> {
    plan(catalog, snapshot, PlanAction::Remove, Some(requested))
}

/// Pure reconciliation diff planning from a supplied snapshot.
///
/// # Errors
///
/// Returns [`ManagerError`] for any unsafe preflight.
pub fn plan_diff(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
) -> Result<ManagementPlan, ManagerError> {
    plan(catalog, snapshot, PlanAction::Diff, None)
}

/// Pure deterministic doctor evaluation from a supplied snapshot.
#[must_use]
pub fn doctor(catalog: &ModuleCatalog, snapshot: &ProjectSnapshot) -> DoctorReport {
    let mut diagnostics = diagnose_snapshot(catalog, snapshot);
    diagnostics.sort();
    diagnostics.dedup();
    DoctorReport {
        schema_version: PLAN_SCHEMA_VERSION,
        healthy: diagnostics.is_empty(),
        diagnostics,
    }
}

struct SelectionChange {
    before: BTreeSet<String>,
    after: BTreeSet<String>,
    added: Vec<String>,
    removed: Vec<String>,
}

fn plan(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    action: PlanAction,
    requested: Option<&str>,
) -> Result<ManagementPlan, ManagerError> {
    let diagnostics = diagnose_snapshot(catalog, snapshot);
    if !diagnostics.is_empty() {
        return Err(ManagerError::Preflight(diagnostics));
    }
    let selection = resolve_selection(catalog, &snapshot.state, action, requested)?;
    if action != PlanAction::Diff && selection.added.is_empty() && selection.removed.is_empty() {
        return finish_plan(
            action,
            requested,
            selection.added,
            selection.removed,
            Vec::new(),
            Vec::new(),
        );
    }

    let mut next_state = build_next_state(catalog, snapshot, action, requested, &selection)?;
    let (mut operations, preserved) =
        build_plan_operations(catalog, snapshot, &selection, &mut next_state)?;
    append_state_operation(catalog, snapshot, &mut next_state, &mut operations)?;
    operations.sort_by(|left, right| {
        left.order()
            .cmp(&right.order())
            .then_with(|| left.path().cmp(right.path()))
    });
    finish_plan(
        action,
        requested,
        selection.added,
        selection.removed,
        operations,
        preserved,
    )
}

fn resolve_selection(
    catalog: &ModuleCatalog,
    state: &ProjectState,
    action: PlanAction,
    requested: Option<&str>,
) -> Result<SelectionChange, ManagerError> {
    let before = selected_ids(state);
    let after = match (action, requested) {
        (PlanAction::Add, Some(module)) => catalog.resolve_add(&before, module)?,
        (PlanAction::Remove, Some(module)) => catalog.resolve_remove(&before, module)?,
        (PlanAction::Diff, None) => before.clone(),
        _ => {
            return Err(ManagerError::InvalidProject(
                "invalid management plan request".to_owned(),
            ));
        }
    };
    let added = after.difference(&before).cloned().collect();
    let removed = before.difference(&after).cloned().collect();
    Ok(SelectionChange {
        before,
        after,
        added,
        removed,
    })
}

fn build_next_state(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    action: PlanAction,
    requested: Option<&str>,
    selection: &SelectionChange,
) -> Result<ProjectState, ManagerError> {
    let mut next_state = snapshot.state.clone();
    let mut ordered_ids = Vec::with_capacity(selection.after.len());
    let mut seen = BTreeSet::new();
    for id in snapshot
        .state
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .chain(catalog.modules.iter().map(|module| module.id.as_str()))
    {
        if selection.after.contains(id) && seen.insert(id) {
            ordered_ids.push(id);
        }
    }
    next_state.modules = ordered_ids
        .into_iter()
        .map(|id| {
            let definition = catalog.module(id).ok_or_else(|| {
                ManagerError::InvalidProject(format!("catalog module `{id}` disappeared"))
            })?;
            Ok(SelectedModule {
                id: id.to_owned(),
                version: definition.version.clone(),
            })
        })
        .collect::<Result<Vec<_>, ManagerError>>()?;
    next_state.providers = next_state
        .modules
        .iter()
        .filter_map(|selected| {
            catalog.module(&selected.id).and_then(|module| {
                module.provider_slot.as_ref().map(|slot| SelectedProvider {
                    slot: slot.clone(),
                    module: selected.id.clone(),
                })
            })
        })
        .collect();
    update_profile_selection(
        &mut next_state,
        action,
        requested,
        &selection.added,
        &selection.removed,
    );
    Ok(next_state)
}

fn build_plan_operations(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selection: &SelectionChange,
    next_state: &mut ProjectState,
) -> Result<(Vec<PlanOperation>, Vec<String>), ManagerError> {
    let mut operations = Vec::new();
    let mut preserved = BTreeSet::new();
    plan_kit_files(
        catalog,
        snapshot,
        &selection.added,
        &selection.removed,
        next_state,
        &mut operations,
        &mut preserved,
    )?;
    plan_regions(
        catalog,
        snapshot,
        &selection.before,
        &selection.after,
        next_state,
        &mut operations,
    )?;
    plan_derived(
        catalog,
        snapshot,
        &selection.before,
        &selection.after,
        next_state,
        &mut operations,
    )?;
    Ok((operations, preserved.into_iter().collect()))
}

fn append_state_operation(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    normalize_next_state(next_state, &catalog.bundle_version);
    let state_content = next_state.to_toml()?;
    let current_state = snapshot.files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject(format!("missing required `{PROJECT_STATE_PATH}`"))
    })?;
    if state_content != *current_state {
        operations.push(PlanOperation::WriteState {
            path: PROJECT_STATE_PATH.to_owned(),
            expected_hash: sha256_hex(current_state.as_bytes()),
            content_hash: sha256_hex(state_content.as_bytes()),
            content: state_content,
        });
    }
    Ok(())
}

pub(crate) fn normalize_next_state(state: &mut ProjectState, kit_version: &str) {
    state.kit_version.clear();
    state.kit_version.push_str(kit_version);
    state.profile.additions.sort();
    state.profile.additions.dedup();
    state.profile.removals.sort();
    state.profile.removals.dedup();
    state.ownership.sort();
    state.ownership.dedup();
    state.managed_regions.sort();
    state.managed_regions.dedup();
}

fn finish_plan(
    action: PlanAction,
    requested: Option<&str>,
    added_modules: Vec<String>,
    removed_modules: Vec<String>,
    operations: Vec<PlanOperation>,
    preserved_paths: Vec<String>,
) -> Result<ManagementPlan, ManagerError> {
    seal_management_plan(ManagementPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: String::new(),
        action,
        requested_module: requested.map(str::to_owned),
        target_version: None,
        added_modules,
        removed_modules,
        operations,
        preserved_paths,
    })
}

pub(crate) fn finish_upgrade_plan(
    target_version: &str,
    mut operations: Vec<PlanOperation>,
    preserved_paths: Vec<String>,
) -> Result<ManagementPlan, ManagerError> {
    operations.sort_by(|left, right| {
        left.order()
            .cmp(&right.order())
            .then_with(|| left.path().cmp(right.path()))
    });
    seal_management_plan(ManagementPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: String::new(),
        action: PlanAction::Upgrade,
        requested_module: None,
        target_version: Some(target_version.to_owned()),
        added_modules: Vec::new(),
        removed_modules: Vec::new(),
        operations,
        preserved_paths,
    })
}

fn seal_management_plan(mut plan: ManagementPlan) -> Result<ManagementPlan, ManagerError> {
    let bytes = serde_json::to_vec(&plan).map_err(ManagerError::BackupEncoding)?;
    plan.plan_id = sha256_hex(&bytes);
    Ok(plan)
}

fn plan_kit_files(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    added: &[String],
    removed: &[String],
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
    preserved: &mut BTreeSet<String>,
) -> Result<(), ManagerError> {
    let mut add_paths = BTreeMap::new();
    for id in added {
        let module = required_module(catalog, id)?;
        for path in module_artifact_paths(module, snapshot)? {
            add_paths.entry(path).or_insert_with(|| id.clone());
        }
    }
    expand_internal_workspace_artifacts(snapshot, &mut add_paths)?;
    for (path, id) in add_paths {
        reject_application_owned(&snapshot.state, &path)?;
        let source = snapshot.kit_sources.get(&path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "approved kit source for module `{id}` is unavailable: `{path}`"
            ))
        })?;
        if let Some(current) = snapshot.files.get(&path) {
            match snapshot.state.ownership_of(&path) {
                Some(OwnershipKind::KitOwned) if current == source => {}
                Some(OwnershipKind::KitOwned) => {
                    return Err(ManagerError::InvalidProject(format!(
                        "refusing kit-owned drift in `{path}`; current bytes do not match approved baseline"
                    )));
                }
                Some(kind) => {
                    return Err(ManagerError::InvalidProject(format!(
                        "refusing module `{id}` target `{path}` owned as {kind:?}"
                    )));
                }
                None => {
                    return Err(ManagerError::InvalidProject(format!(
                        "refusing existing unowned module target `{path}`"
                    )));
                }
            }
            continue;
        }
        operations.push(PlanOperation::CreateFile {
            path: path.clone(),
            content_hash: sha256_hex(source.as_bytes()),
            content: source.clone(),
        });
        next_state.ownership.push(OwnershipRecord {
            path,
            kind: OwnershipKind::KitOwned,
        });
    }

    let mut remove_paths = BTreeMap::new();
    for id in removed {
        let module = required_module(catalog, id)?;
        for resource in &module.persistence {
            preserved.insert(resource.clone());
        }
        for path in module_artifact_paths(module, snapshot)? {
            remove_paths.entry(path).or_insert_with(|| id.clone());
        }
    }
    for (path, id) in remove_paths {
        if preserves_historical_path(&path) {
            preserved.insert(path);
            continue;
        }
        if artifact_required_by_selected(catalog, snapshot, next_state, &path)? {
            continue;
        }
        reject_application_owned(&snapshot.state, &path)?;
        let Some(current) = snapshot.files.get(&path) else {
            if snapshot.state.ownership_of(&path).is_some() {
                return Err(ManagerError::InvalidProject(format!(
                    "owned module file `{path}` is missing"
                )));
            }
            continue;
        };
        if snapshot.state.ownership_of(&path) != Some(OwnershipKind::KitOwned) {
            return Err(ManagerError::InvalidProject(format!(
                "refusing removal of non-kit-owned file `{path}`"
            )));
        }
        let source = snapshot.kit_sources.get(&path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "approved removal baseline for module `{id}` is unavailable: `{path}`"
            ))
        })?;
        if current != source {
            return Err(ManagerError::InvalidProject(format!(
                "refusing removal of edited kit-owned file `{path}`"
            )));
        }
        operations.push(PlanOperation::RemoveFile {
            path: path.clone(),
            expected_hash: sha256_hex(current.as_bytes()),
        });
        next_state.ownership.retain(|record| record.path != path);
    }
    Ok(())
}
fn expand_internal_workspace_artifacts(
    snapshot: &ProjectSnapshot,
    artifacts: &mut BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    loop {
        let manifests = artifacts
            .keys()
            .filter(|path| path.ends_with("/Cargo.toml"))
            .cloned()
            .collect::<Vec<_>>();
        let mut discovered = Vec::new();
        for manifest_path in manifests {
            let manifest = snapshot.kit_sources.get(&manifest_path).ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "approved manifest baseline is unavailable: `{manifest_path}`"
                ))
            })?;
            for dependency in manifest_workspace_dependencies(manifest, &manifest_path)? {
                let value = snapshot
                    .workspace_dependencies
                    .get(&dependency)
                    .ok_or_else(|| {
                        ManagerError::InvalidProject(format!(
                            "kit workspace dependency `{dependency}` is unavailable"
                        ))
                    })?;
                let Some(path) = workspace_dependency_path(value)? else {
                    continue;
                };
                let cargo_path = format!("{path}/Cargo.toml");
                if artifacts.contains_key(&cargo_path) {
                    continue;
                }
                let prefix = format!("{path}/");
                let dependency_artifacts = snapshot
                    .kit_sources
                    .keys()
                    .filter(|candidate| {
                        candidate.as_str() == cargo_path || candidate.starts_with(&prefix)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if dependency_artifacts.is_empty() {
                    return Err(ManagerError::InvalidProject(format!(
                        "internal workspace dependency `{dependency}` has no approved artifacts at `{path}`"
                    )));
                }
                discovered.extend(
                    dependency_artifacts
                        .into_iter()
                        .map(|artifact| (artifact, format!("workspace dependency `{dependency}`"))),
                );
            }
        }
        let mut changed = false;
        for (path, source) in discovered {
            if let std::collections::btree_map::Entry::Vacant(entry) = artifacts.entry(path) {
                entry.insert(source);
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
    }
}

fn plan_regions(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let mut references = BTreeSet::new();
    for id in before.union(after) {
        let module = required_module(catalog, id)?;
        references.extend(module.generator_ownership.managed_regions.iter().cloned());
    }
    let mut by_path: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for record in &next_state.managed_regions {
        by_path
            .entry(record.path.clone())
            .or_default()
            .push(record.id.clone());
    }
    for reference in references {
        let Some((pattern, region_id)) = reference.rsplit_once('#') else {
            continue;
        };
        let targets = if pattern.contains('*') {
            matching_snapshot_paths(&snapshot.files, pattern)
        } else {
            vec![pattern.to_owned()]
        };
        if targets.is_empty() {
            return Err(ManagerError::InvalidProject(format!(
                "managed path pattern `{pattern}` matched no project file"
            )));
        }
        for path in targets {
            by_path.entry(path).or_default().push(region_id.to_owned());
        }
    }

    for (path, mut region_ids) in by_path {
        reject_application_owned(&snapshot.state, &path)?;
        region_ids.sort();
        region_ids.dedup();
        let current = snapshot.files.get(&path).ok_or_else(|| {
            ManagerError::InvalidProject(format!("managed-region target `{path}` is missing"))
        })?;
        let mut reconciled = current.clone();
        for region_id in &region_ids {
            let expected = next_state
                .managed_region(&path, region_id)
                .cloned()
                .ok_or_else(|| {
                    ManagerError::InvalidProject(format!(
                        "managed region `{region_id}` in `{path}` has no state ownership record"
                    ))
                })?;
            let desired = render_region(region_id, after, &next_state.ownership, snapshot)?;
            reconciled = reconcile_managed_region(&reconciled, &expected, &desired)?;
            let record = next_state
                .managed_regions
                .iter_mut()
                .find(|record| record.path == path && record.id == *region_id)
                .ok_or_else(|| {
                    ManagerError::InvalidProject(format!(
                        "managed region `{region_id}` disappeared from project state"
                    ))
                })?;
            record.marker_version = MANAGED_MARKER_VERSION;
            record.content_hash = sha256_hex(desired.as_bytes());
        }
        if reconciled != *current {
            operations.push(PlanOperation::ReconcileRegions {
                path,
                expected_hash: sha256_hex(current.as_bytes()),
                content_hash: sha256_hex(reconciled.as_bytes()),
                region_ids,
                content: reconciled,
            });
        }
    }
    Ok(())
}

fn plan_derived(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let mut paths = BTreeSet::new();
    for id in before.union(after) {
        let module = required_module(catalog, id)?;
        paths.extend(
            module
                .generator_ownership
                .derived
                .iter()
                .filter(|path| MANAGER_DERIVED_PATHS.contains(&path.as_str()))
                .cloned(),
        );
    }
    for path in paths {
        reject_application_owned(&snapshot.state, &path)?;
        let desired = render_derived(&path, catalog, after)?;
        if let Some(current) = snapshot.files.get(&path) {
            if snapshot.state.ownership_of(&path) != Some(OwnershipKind::Derived) {
                return Err(ManagerError::InvalidProject(format!(
                    "refusing to regenerate non-derived file `{path}`"
                )));
            }
            let baseline = render_derived(&path, catalog, before)?;
            if current != &baseline {
                return Err(ManagerError::InvalidProject(format!(
                    "refusing edited derived file `{path}`; run doctor before retrying"
                )));
            }
            if current != &desired {
                operations.push(PlanOperation::RegenerateDerived {
                    path: path.clone(),
                    expected_hash: Some(sha256_hex(current.as_bytes())),
                    content_hash: sha256_hex(desired.as_bytes()),
                    content: desired,
                });
            }
            continue;
        }
        if snapshot.state.ownership_of(&path).is_some() {
            return Err(ManagerError::InvalidProject(format!(
                "owned derived file `{path}` is missing"
            )));
        }
        operations.push(PlanOperation::RegenerateDerived {
            path: path.clone(),
            expected_hash: None,
            content_hash: sha256_hex(desired.as_bytes()),
            content: desired,
        });
        next_state.ownership.push(OwnershipRecord {
            path,
            kind: OwnershipKind::Derived,
        });
    }
    Ok(())
}

fn diagnose_snapshot(catalog: &ModuleCatalog, snapshot: &ProjectSnapshot) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Err(error) = catalog.validate() {
        diagnostics.push(diagnostic("catalog-invalid", None, error.to_string()));
        return diagnostics;
    }
    if let Err(error) = snapshot.state.validate() {
        diagnostics.push(diagnostic(
            "state-invalid",
            Some(PROJECT_STATE_PATH),
            error.to_string(),
        ));
        return diagnostics;
    }

    let selected = selected_ids(&snapshot.state);
    diagnose_state_selection(catalog, snapshot, &selected, &mut diagnostics);
    diagnose_profile_artifacts(catalog, snapshot, &selected, &mut diagnostics);
    diagnose_owned_files(catalog, snapshot, &selected, &mut diagnostics);
    let recorded = diagnose_managed_records(snapshot, &selected, &mut diagnostics);
    diagnose_untracked_regions(snapshot, &recorded, &mut diagnostics);
    diagnostics.sort();
    diagnostics.dedup();
    diagnostics
}

fn diagnose_state_selection(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if snapshot.state.ownership_of(PROJECT_STATE_PATH) != Some(OwnershipKind::KitOwned) {
        diagnostics.push(diagnostic(
            "state-ownership-invalid",
            Some(PROJECT_STATE_PATH),
            "project state must be kit-owned so successful plans can commit state last".to_owned(),
        ));
    }
    if snapshot.state.kit_version != catalog.bundle_version {
        diagnostics.push(diagnostic(
            "kit-version-mismatch",
            Some(PROJECT_STATE_PATH),
            format!(
                "project kit version {} does not match catalog bundle {}",
                snapshot.state.kit_version, catalog.bundle_version
            ),
        ));
    }
    for module in &snapshot.state.modules {
        match catalog.module(&module.id) {
            Some(definition) if definition.version == module.version => {}
            Some(definition) => diagnostics.push(diagnostic(
                "module-version-mismatch",
                Some(PROJECT_STATE_PATH),
                format!(
                    "module `{}` records version {}, catalog requires {}",
                    module.id, module.version, definition.version
                ),
            )),
            None => diagnostics.push(diagnostic(
                "unknown-module",
                Some(PROJECT_STATE_PATH),
                format!("project selects unknown module `{}`", module.id),
            )),
        }
    }
    if let Err(error) = catalog.validate_selection(selected) {
        diagnostics.push(diagnostic(
            "selection-invalid",
            Some(PROJECT_STATE_PATH),
            error.to_string(),
        ));
    }
}

fn diagnose_profile_artifacts(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for id in &snapshot.state.profile.additions {
        if !selected.contains(id) {
            diagnostics.push(diagnostic(
                "profile-addition-missing",
                Some(PROJECT_STATE_PATH),
                format!("profile addition `{id}` is not selected"),
            ));
            continue;
        }
        let Some(module) = catalog.module(id) else {
            continue;
        };
        match module_artifact_paths(module, snapshot) {
            Ok(paths) => diagnose_module_artifact_paths(snapshot, id, paths, diagnostics),
            Err(error) => diagnostics.push(diagnostic(
                "module-artifact-source-missing",
                None,
                error.to_string(),
            )),
        }
    }
    for id in &snapshot.state.profile.removals {
        if selected.contains(id) {
            diagnostics.push(diagnostic(
                "profile-removal-selected",
                Some(PROJECT_STATE_PATH),
                format!("profile removal `{id}` remains selected"),
            ));
        }
    }
}

fn diagnose_module_artifact_paths(
    snapshot: &ProjectSnapshot,
    module_id: &str,
    paths: BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for path in paths {
        if snapshot.state.ownership_of(&path) != Some(OwnershipKind::KitOwned)
            || !snapshot.files.contains_key(&path)
        {
            diagnostics.push(diagnostic(
                "module-artifact-missing",
                Some(&path),
                format!("explicitly added module `{module_id}` is missing owned artifact `{path}`"),
            ));
        }
    }
}

fn diagnose_owned_files(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for ownership in &snapshot.state.ownership {
        let Some(contents) = snapshot.files.get(&ownership.path) else {
            diagnostics.push(diagnostic(
                "owned-file-missing",
                Some(&ownership.path),
                format!("owned file `{}` is missing", ownership.path),
            ));
            continue;
        };
        match ownership.kind {
            OwnershipKind::KitOwned if ownership.path == PROJECT_STATE_PATH => {}
            OwnershipKind::KitOwned => {
                diagnose_kit_owned_file(snapshot, ownership, contents, diagnostics);
            }
            OwnershipKind::Derived if ownership.path == "Cargo.lock" => {}
            OwnershipKind::Derived => {
                diagnose_derived_file(catalog, selected, ownership, contents, diagnostics);
            }
            OwnershipKind::ApplicationOwned => {}
        }
    }
}

fn diagnose_kit_owned_file(
    snapshot: &ProjectSnapshot,
    ownership: &OwnershipRecord,
    contents: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(source) = snapshot.kit_sources.get(&ownership.path) else {
        diagnostics.push(diagnostic(
            "kit-baseline-missing",
            Some(&ownership.path),
            format!(
                "approved baseline for kit-owned file `{}` is unavailable",
                ownership.path
            ),
        ));
        return;
    };
    if matches_approved_baseline(&ownership.path, contents, source, &snapshot.state) == Ok(false) {
        diagnostics.push(diagnostic(
            "kit-owned-drift",
            Some(&ownership.path),
            format!(
                "kit-owned file `{}` differs from its approved baseline outside managed regions",
                ownership.path
            ),
        ));
    }
}

fn diagnose_derived_file(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    ownership: &OwnershipRecord,
    contents: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match render_derived(&ownership.path, catalog, selected) {
        Ok(expected) if expected == contents => {}
        Ok(_) => diagnostics.push(diagnostic(
            "derived-drift",
            Some(&ownership.path),
            format!("derived file `{}` is not current", ownership.path),
        )),
        Err(error) => diagnostics.push(diagnostic(
            "derived-unsupported",
            Some(&ownership.path),
            error.to_string(),
        )),
    }
}

fn diagnose_managed_records<'a>(
    snapshot: &'a ProjectSnapshot,
    selected: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeSet<(&'a str, &'a str)> {
    let mut recorded = BTreeSet::new();
    for record in &snapshot.state.managed_regions {
        recorded.insert((record.path.as_str(), record.id.as_str()));
        diagnose_managed_record(snapshot, selected, record, diagnostics);
    }
    recorded
}

fn diagnose_managed_record(
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    record: &ManagedRegionRecord,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(contents) = snapshot.files.get(&record.path) else {
        diagnostics.push(diagnostic(
            "managed-file-missing",
            Some(&record.path),
            format!("managed-region file `{}` is missing", record.path),
        ));
        return;
    };
    let regions = match parse_managed_regions(contents) {
        Ok(regions) => regions,
        Err(error) => {
            diagnostics.push(diagnostic(
                "managed-region-corrupt",
                Some(&record.path),
                error.to_string(),
            ));
            return;
        }
    };
    let Some(region) = regions.iter().find(|region| region.id == record.id) else {
        diagnostics.push(diagnostic(
            "managed-region-missing",
            Some(&record.path),
            format!("managed region `{}` is missing", record.id),
        ));
        return;
    };
    if region.marker_version != record.marker_version || region.content_hash != record.content_hash
    {
        diagnostics.push(diagnostic(
            "managed-region-state-mismatch",
            Some(&record.path),
            format!(
                "managed region `{}` marker metadata differs from project state",
                record.id
            ),
        ));
        return;
    }
    if default_profile_modules_region(snapshot, record, region.content) {
        return;
    }
    match render_region(&record.id, selected, &snapshot.state.ownership, snapshot) {
        Ok(expected) if expected == region.content => {}
        Ok(_) => diagnostics.push(diagnostic(
            "managed-region-drift",
            Some(&record.path),
            format!(
                "managed region `{}` does not match selected modules",
                record.id
            ),
        )),
        Err(error) => diagnostics.push(diagnostic(
            "managed-region-render-failed",
            Some(&record.path),
            error.to_string(),
        )),
    }
}

fn default_profile_modules_region(
    snapshot: &ProjectSnapshot,
    record: &ManagedRegionRecord,
    content: &str,
) -> bool {
    record.id == "modules"
        && snapshot.state.profile.additions.is_empty()
        && snapshot.state.profile.removals.is_empty()
        && content.is_empty()
}

fn diagnose_untracked_regions(
    snapshot: &ProjectSnapshot,
    recorded: &BTreeSet<(&str, &str)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (path, contents) in &snapshot.files {
        match parse_managed_regions(contents) {
            Ok(regions) => {
                let baseline_regions = snapshot
                    .kit_sources
                    .get(path)
                    .and_then(|baseline| parse_managed_regions(baseline).ok())
                    .unwrap_or_default();
                for region in regions {
                    if recorded.contains(&(path.as_str(), region.id)) {
                        continue;
                    }
                    let approved_baseline = baseline_regions.iter().any(|baseline| {
                        baseline.id == region.id
                            && baseline.marker_version == region.marker_version
                            && baseline.content_hash == region.content_hash
                            && baseline.content == region.content
                    });
                    if !approved_baseline {
                        diagnostics.push(diagnostic(
                            "managed-region-untracked",
                            Some(path),
                            format!("managed region `{}` has no project state record", region.id),
                        ));
                    }
                }
            }
            Err(error) if contents.contains("omnius:managed-") => diagnostics.push(diagnostic(
                "managed-region-corrupt",
                Some(path),
                error.to_string(),
            )),
            Err(_) => {}
        }
    }
}

fn matches_approved_baseline(
    path: &str,
    contents: &str,
    baseline: &str,
    state: &ProjectState,
) -> Result<bool, RegionError> {
    let mut normalized = contents.to_owned();
    let baseline_regions = parse_managed_regions(baseline)?;
    let mut records: Vec<&ManagedRegionRecord> = state
        .managed_regions
        .iter()
        .filter(|record| record.path == path)
        .collect();
    records.sort_by(|left, right| left.id.cmp(&right.id));
    for record in records {
        let baseline_region = baseline_regions
            .iter()
            .find(|region| region.id == record.id)
            .ok_or_else(|| {
                RegionError::new(format!(
                    "approved baseline for `{path}` is missing managed region `{}`",
                    record.id
                ))
            })?;
        normalized = reconcile_managed_region(&normalized, record, baseline_region.content)?;
    }
    Ok(normalized == baseline)
}

fn render_region(
    id: &str,
    selected: &BTreeSet<String>,
    ownership: &[OwnershipRecord],
    snapshot: &ProjectSnapshot,
) -> Result<String, ManagerError> {
    match id {
        "workspace-members" => {
            let mut members = BTreeSet::new();
            for record in ownership {
                if record.kind != OwnershipKind::KitOwned
                    || !(record.path.starts_with("crates/") || record.path.starts_with("apps/"))
                    || !record.path.ends_with("/Cargo.toml")
                    || record.path.split('/').count() != 3
                {
                    continue;
                }
                let member = record.path.trim_end_matches("/Cargo.toml");
                if matches!(member, "crates/service-kit" | "apps/service") {
                    continue;
                }
                members.insert(member);
            }
            let mut content = String::new();
            for member in members {
                content.push_str("  \"");
                content.push_str(member);
                content.push_str("\",\n");
            }
            Ok(content)
        }
        "workspace-dependencies" => render_workspace_dependencies(ownership, snapshot),
        "modules" => Ok(render_modules_region(selected)),
        _ => Err(ManagerError::InvalidProject(format!(
            "no deterministic renderer exists for managed region `{id}`"
        ))),
    }
}
pub(crate) fn render_modules_region(selected: &BTreeSet<String>) -> String {
    let mut content = String::new();
    for module in selected {
        content.push_str("    \"");
        content.push_str(module);
        content.push_str("\",\n");
    }
    content
}

fn render_workspace_dependencies(
    ownership: &[OwnershipRecord],
    snapshot: &ProjectSnapshot,
) -> Result<String, ManagerError> {
    let baseline = snapshot.kit_sources.get("Cargo.toml").ok_or_else(|| {
        ManagerError::InvalidProject(
            "base Cargo.toml baseline is unavailable for dependency reconciliation".to_owned(),
        )
    })?;
    let static_dependencies = dependency_table_names(baseline, "base Cargo.toml")?;
    let mut required = BTreeSet::new();
    for record in ownership {
        if record.kind != OwnershipKind::KitOwned
            || !(record.path.starts_with("crates/") || record.path.starts_with("apps/"))
            || !record.path.ends_with("/Cargo.toml")
            || record.path.split('/').count() != 3
            || matches!(
                record.path.as_str(),
                "crates/service-kit/Cargo.toml" | "apps/service/Cargo.toml"
            )
        {
            continue;
        }
        let manifest = snapshot.kit_sources.get(&record.path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "approved manifest baseline is unavailable: `{}`",
                record.path
            ))
        })?;
        required.extend(manifest_workspace_dependencies(manifest, &record.path)?);
    }

    let owned_paths: BTreeSet<&str> = ownership
        .iter()
        .filter(|record| record.kind == OwnershipKind::KitOwned)
        .map(|record| record.path.as_str())
        .collect();
    let mut content = String::new();
    for dependency in required.difference(&static_dependencies) {
        let value = snapshot
            .workspace_dependencies
            .get(dependency)
            .ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "kit workspace dependency `{dependency}` is unavailable"
                ))
            })?;
        if let Some(path) = workspace_dependency_path(value)? {
            let manifest_path = format!("{path}/Cargo.toml");
            if !owned_paths.contains(manifest_path.as_str()) {
                return Err(ManagerError::InvalidProject(format!(
                    "module artifact requires internal workspace dependency `{dependency}` at `{path}`, but the catalog dependency closure did not install it"
                )));
            }
        }
        content.push_str(dependency);
        content.push_str(" = ");
        content.push_str(value);
        content.push('\n');
    }
    Ok(content)
}

fn dependency_table_names(manifest: &str, label: &str) -> Result<BTreeSet<String>, ManagerError> {
    let document: toml::Value = toml::from_str(manifest)
        .map_err(|error| ManagerError::InvalidProject(format!("cannot parse {label}: {error}")))?;
    Ok(document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .map(|dependencies| dependencies.keys().cloned().collect())
        .unwrap_or_default())
}

fn manifest_workspace_dependencies(
    manifest: &str,
    path: &str,
) -> Result<BTreeSet<String>, ManagerError> {
    let document: toml::Value = toml::from_str(manifest).map_err(|error| {
        ManagerError::InvalidProject(format!("cannot parse module manifest `{path}`: {error}"))
    })?;
    let mut dependencies = BTreeSet::new();
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = document.get(table_name).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, value) in table {
            if value
                .as_table()
                .and_then(|definition| definition.get("workspace"))
                .and_then(toml::Value::as_bool)
                == Some(true)
            {
                dependencies.insert(name.clone());
            }
        }
    }
    Ok(dependencies)
}

fn workspace_dependency_path(value: &str) -> Result<Option<String>, ManagerError> {
    let document: toml::Value =
        toml::from_str(&format!("dependency = {value}")).map_err(|error| {
            ManagerError::InvalidProject(format!(
                "cannot parse workspace dependency definition `{value}`: {error}"
            ))
        })?;
    Ok(document
        .get("dependency")
        .and_then(toml::Value::as_table)
        .and_then(|definition| definition.get("path"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned))
}

pub(crate) const MANAGER_DERIVED_PATHS: &[&str] =
    &["config/reference.toml", "docs/module-catalog.md"];

pub(crate) fn render_derived(
    path: &str,
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
) -> Result<String, ManagerError> {
    match path {
        "docs/module-catalog.md" => {
            let mut output = String::from(
                "# Selected service modules\n\n| Module | Version | Provider slot |\n|---|---:|---|\n",
            );
            for id in selected {
                let module = required_module(catalog, id)?;
                output.push_str("| `");
                output.push_str(&module.id);
                output.push_str("` | `");
                output.push_str(&module.version);
                output.push_str("` | ");
                output.push_str(module.provider_slot.as_deref().unwrap_or("-"));
                output.push_str(" |\n");
            }
            Ok(output)
        }
        "config/reference.toml" => {
            let mut output = String::from("# Generated module configuration namespaces.\n");
            for id in selected {
                let module = required_module(catalog, id)?;
                output.push('\n');
                output.push('[');
                output.push_str(&module.configuration.prefix);
                output.push_str("]\n");
            }
            Ok(output)
        }
        _ => Err(ManagerError::InvalidProject(format!(
            "no deterministic derived renderer exists for `{path}`"
        ))),
    }
}

fn update_profile_selection(
    state: &mut ProjectState,
    action: PlanAction,
    requested: Option<&str>,
    added: &[String],
    removed: &[String],
) {
    let Some(requested) = requested else {
        return;
    };
    match action {
        PlanAction::Add if !added.is_empty() => {
            for id in added {
                if let Some(index) = state
                    .profile
                    .removals
                    .iter()
                    .position(|removed| removed == id)
                {
                    state.profile.removals.remove(index);
                } else if !state.profile.additions.contains(id) {
                    state.profile.additions.push(id.clone());
                }
            }
        }
        PlanAction::Remove if !removed.is_empty() => {
            if let Some(index) = state
                .profile
                .additions
                .iter()
                .position(|id| id == requested)
            {
                state.profile.additions.remove(index);
            } else if !state.profile.removals.iter().any(|id| id == requested) {
                state.profile.removals.push(requested.to_owned());
            }
        }
        PlanAction::Add | PlanAction::Remove | PlanAction::Diff | PlanAction::Upgrade => {}
    }
}

fn selected_ids(state: &ProjectState) -> BTreeSet<String> {
    state
        .modules
        .iter()
        .map(|module| module.id.clone())
        .collect()
}

fn required_module<'a>(
    catalog: &'a ModuleCatalog,
    id: &str,
) -> Result<&'a ModuleDefinition, ManagerError> {
    catalog.module(id).ok_or_else(|| {
        ManagerError::InvalidProject(format!("project selects unknown module `{id}`"))
    })
}

fn module_artifact_paths(
    module: &ModuleDefinition,
    snapshot: &ProjectSnapshot,
) -> Result<BTreeSet<String>, ManagerError> {
    let mut artifacts = BTreeSet::new();
    for declared in &module.generator_ownership.kit_owned {
        let mut matched = false;
        if snapshot.kit_sources.contains_key(declared) {
            matched = true;
            artifacts.insert(declared.clone());
        }
        let prefix = if declared.ends_with("/Cargo.toml") {
            format!("{}/", declared.trim_end_matches("/Cargo.toml"))
        } else {
            format!("{declared}/")
        };
        for path in snapshot
            .kit_sources
            .keys()
            .filter(|path| path.starts_with(&prefix))
        {
            matched = true;
            artifacts.insert(path.clone());
        }
        if !matched {
            return Err(ManagerError::InvalidProject(format!(
                "approved kit artifact for module `{}` is unavailable: `{declared}`",
                module.id
            )));
        }
    }
    if module.id == "generator" {
        artifacts.extend(
            snapshot
                .kit_sources
                .keys()
                .filter(|path| {
                    path.starts_with("specs/machine/")
                        || path.starts_with("templates/base-service/")
                })
                .cloned(),
        );
    }
    Ok(artifacts)
}

fn artifact_required_by_selected(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    state: &ProjectState,
    path: &str,
) -> Result<bool, ManagerError> {
    for selected in &state.modules {
        let module = required_module(catalog, &selected.id)?;
        if selected.id == "generator"
            && (path.starts_with("specs/machine/") || path.starts_with("templates/base-service/"))
        {
            return Ok(true);
        }
        for declared in &module.generator_ownership.kit_owned {
            if declared == path {
                return Ok(true);
            }
            let prefix = if declared.ends_with("/Cargo.toml") {
                format!("{}/", declared.trim_end_matches("/Cargo.toml"))
            } else if !snapshot.kit_sources.contains_key(declared) {
                format!("{declared}/")
            } else {
                continue;
            };
            if path.starts_with(&prefix) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn ensure_safe_project_path(root: &Path, relative: &str) -> Result<(), ManagerError> {
    validate_relative_path(relative)?;
    let root_metadata = fs::symlink_metadata(root).map_err(|source| ManagerError::Filesystem {
        path: root.to_path_buf(),
        source,
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ManagerError::InvalidProject(format!(
            "project root must be a real directory, not a symlink: {}",
            root.display()
        )));
    }
    let mut current = root.to_path_buf();
    let components: Vec<&str> = relative.split('/').collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ManagerError::InvalidProject(format!(
                        "managed path has a symlinked component: `{relative}`"
                    )));
                }
                if index + 1 < components.len() && !metadata.is_dir() {
                    return Err(ManagerError::InvalidProject(format!(
                        "managed path has a non-directory ancestor: `{relative}`"
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
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

fn reject_application_owned(state: &ProjectState, path: &str) -> Result<(), ManagerError> {
    if state.ownership_of(path) == Some(OwnershipKind::ApplicationOwned) {
        return Err(ManagerError::InvalidProject(format!(
            "refusing generator change to application-owned file `{path}`"
        )));
    }
    Ok(())
}

fn remove_empty_ancestors(path: &Path, root: &Path) -> Result<(), ManagerError> {
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory == root || !directory.starts_with(root) {
            break;
        }
        let empty = fs::read_dir(directory)
            .map_err(|source| ManagerError::Filesystem {
                path: directory.to_path_buf(),
                source,
            })?
            .next()
            .transpose()
            .map_err(|source| ManagerError::Filesystem {
                path: directory.to_path_buf(),
                source,
            })?
            .is_none();
        if !empty {
            break;
        }
        fs::remove_dir(directory).map_err(|source| ManagerError::Filesystem {
            path: directory.to_path_buf(),
            source,
        })?;
        current = directory.parent();
    }
    Ok(())
}

fn matching_snapshot_paths(files: &BTreeMap<String, String>, pattern: &str) -> Vec<String> {
    files
        .keys()
        .filter(|path| path_matches_pattern(path, pattern))
        .cloned()
        .collect()
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let path_parts: Vec<&str> = path.split('/').collect();
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    path_parts.len() == pattern_parts.len()
        && path_parts
            .iter()
            .zip(pattern_parts)
            .all(|(value, expected)| expected == "*" || *value == expected)
}

fn expand_pattern(root: &Path, pattern: &str) -> Result<Vec<String>, ManagerError> {
    let parts: Vec<&str> = pattern.split('/').collect();
    let Some(wildcard) = parts.iter().position(|part| *part == "*") else {
        return Ok(vec![pattern.to_owned()]);
    };
    if parts.iter().filter(|part| **part == "*").count() != 1 {
        return Err(ManagerError::InvalidProject(format!(
            "catalog path pattern supports exactly one wildcard component: `{pattern}`"
        )));
    }
    let parent = parts[..wildcard]
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part));
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(ManagerError::Filesystem {
                path: parent,
                source,
            });
        }
    };
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ManagerError::Filesystem {
            path: parent.clone(),
            source,
        })?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            ManagerError::InvalidProject(format!("non-UTF-8 path below {}", parent.display()))
        })?;
        let mut candidate = parts.clone();
        candidate[wildcard] = name;
        let relative = candidate.join("/");
        if root.join(&relative).is_file() {
            matches.push(relative);
        }
    }
    matches.sort();
    Ok(matches)
}

fn collect_catalog_kit_sources(
    root: &Path,
    catalog: &ModuleCatalog,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    for module in &catalog.modules {
        for path in &module.generator_ownership.kit_owned {
            collect_kit_source(root, path, sources)?;
        }
        if module.id == "generator" {
            collect_kit_source(root, "specs/machine/module-catalog.yaml", sources)?;
            collect_kit_source(root, "specs/machine/profiles.yaml", sources)?;
            collect_kit_tree(
                root,
                "templates/base-service",
                "templates/base-service",
                sources,
            )?;
        }
    }
    Ok(())
}

/// Returns whether a path names migrations, persisted data, or history that
/// module removal must retain.
#[must_use]
pub fn preserves_historical_path(path: &str) -> bool {
    path.split('/')
        .any(|component| matches!(component, "migration" | "migrations" | "data" | "history"))
}

fn diagnostic(code: &str, path: Option<&str>, message: String) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        path: path.map(str::to_owned),
        message,
    }
}

fn collect_kit_source(
    root: &Path,
    declared: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    validate_relative_path(declared)?;
    let source_path = if root.join(declared).exists() {
        declared
    } else {
        match declared {
            "crates/sse/Cargo.toml" => "crates/realtime-sse/Cargo.toml",
            "crates/websockets/Cargo.toml" => "crates/realtime-websocket/Cargo.toml",
            _ => declared,
        }
    };
    let absolute = root.join(source_path);
    let metadata = match fs::symlink_metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ManagerError::Filesystem {
                path: absolute,
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(ManagerError::InvalidProject(format!(
            "kit artifact may not be a symlink: {source_path}"
        )));
    }
    if metadata.is_dir() {
        collect_kit_tree(root, source_path, declared, sources)
    } else if metadata.is_file() && declared.ends_with("/Cargo.toml") {
        let source_parent = source_path.trim_end_matches("/Cargo.toml");
        let target_parent = declared.trim_end_matches("/Cargo.toml");
        collect_kit_tree(root, source_parent, target_parent, sources)
    } else if metadata.is_file() {
        let contents = read_required_file(&absolute)?;
        sources.insert(declared.to_owned(), contents);
        Ok(())
    } else {
        Err(ManagerError::InvalidProject(format!(
            "kit artifact is not a regular file or directory: `{source_path}`"
        )))
    }
}

fn collect_kit_tree(
    root: &Path,
    source_relative: &str,
    target_relative: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    let absolute = root.join(source_relative);
    let mut entries = fs::read_dir(&absolute)
        .map_err(|source| ManagerError::Filesystem {
            path: absolute.clone(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ManagerError::Filesystem {
            path: absolute.clone(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().into_string().map_err(|_| {
            ManagerError::InvalidProject(format!(
                "kit artifact contains a non-UTF-8 path below `{source_relative}`"
            ))
        })?;
        let source_child = if source_relative.is_empty() {
            name.clone()
        } else {
            format!("{source_relative}/{name}")
        };
        let target_child = if target_relative.is_empty() {
            name
        } else {
            format!("{target_relative}/{name}")
        };
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|source| ManagerError::Filesystem {
                path: entry.path(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(ManagerError::InvalidProject(format!(
                "kit artifact may not contain symlinks: `{source_child}`"
            )));
        }
        if metadata.is_dir() {
            collect_kit_tree(root, &source_child, &target_child, sources)?;
        } else if metadata.is_file() {
            sources.insert(target_child, read_required_file(&entry.path())?);
        } else {
            return Err(ManagerError::InvalidProject(format!(
                "kit artifact contains a non-file entry: `{source_child}`"
            )));
        }
    }
    Ok(())
}

fn load_kit_workspace_dependencies(root: &Path) -> Result<BTreeMap<String, String>, ManagerError> {
    let mut dependencies = load_workspace_dependencies(&root.join("Cargo.toml"))?;
    let template = root.join("templates/base-service/Cargo.toml");
    if template.is_file() {
        for (name, value) in load_workspace_dependencies(&template)? {
            dependencies.entry(name).or_insert(value);
        }
    }
    Ok(dependencies)
}

fn load_workspace_dependencies(path: &Path) -> Result<BTreeMap<String, String>, ManagerError> {
    let source = read_required_file(path)?;
    let document: toml::Value = toml::from_str(&source).map_err(|error| {
        ManagerError::InvalidProject(format!(
            "cannot parse kit workspace dependencies from {}: {error}",
            path.display()
        ))
    })?;
    let dependencies = document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "kit workspace has no [workspace.dependencies]: {}",
                path.display()
            ))
        })?;
    Ok(dependencies
        .iter()
        .map(|(name, value)| {
            let value = value
                .to_string()
                .replace("crates/realtime-sse", "crates/sse")
                .replace("crates/realtime-websocket", "crates/websockets");
            (name.clone(), value)
        })
        .collect())
}

fn read_required_file(path: &Path) -> Result<String, ManagerError> {
    read_optional_file(path)?.ok_or_else(|| {
        ManagerError::InvalidProject(format!("required file is missing: {}", path.display()))
    })
}

fn read_optional_file(path: &Path) -> Result<Option<String>, ManagerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ManagerError::Filesystem {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(ManagerError::InvalidProject(format!(
            "managed path is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = fs::read(path).map_err(|source| ManagerError::Filesystem {
        path: path.to_path_buf(),
        source,
    })?;
    String::from_utf8(bytes).map(Some).map_err(|_| {
        ManagerError::InvalidProject(format!("managed file is not UTF-8: {}", path.display()))
    })
}

fn atomic_write(path: &Path, content: &str, plan_id: &str) -> Result<(), ManagerError> {
    let parent = path.parent().ok_or_else(|| {
        ManagerError::InvalidProject(format!("managed path has no parent: {}", path.display()))
    })?;
    fs::create_dir_all(parent).map_err(|source| ManagerError::Filesystem {
        path: parent.to_path_buf(),
        source,
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "managed path has invalid name: {}",
                path.display()
            ))
        })?;
    let temporary = parent.join(format!(".{name}.omnius-{}.tmp", &plan_id[..16]));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temporary)
        .map_err(|source| ManagerError::Filesystem {
            path: temporary.clone(),
            source,
        })?;
    if let Err(source) = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&temporary);
        return Err(ManagerError::Filesystem {
            path: temporary,
            source,
        });
    }
    drop(file);
    fs::rename(&temporary, path).map_err(|source| {
        let _ = fs::remove_file(&temporary);
        ManagerError::Filesystem {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[derive(Serialize)]
struct BackupArtifact {
    schema_version: u32,
    plan_id: String,
    entries: Vec<BackupEntry>,
}

#[derive(Serialize)]
struct BackupEntry {
    path: String,
    previous: Option<String>,
}
