use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsStr,
    fmt::{self, Write as _},
    fs, io,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    application_templates::{
        APPLICATION_TEMPLATE_DESCRIPTORS, application_template,
        validate_application_template_catalog,
    },
    cargo_resolver::{
        CargoLockfileResolver, CargoResolverError, CargoResolverRequest, CargoResolverResult,
        LockfileResolver,
    },
    catalog::ProfileCatalog,
    journal::{JournalOperation, LifecycleLock},
    lifecycle::{
        ExistingProjectStages, LifecycleError, read_regular_bytes, remove_project_file,
        verify_project_inputs, write_project_file,
    },
    modules::{
        CatalogError, ComposeMigration, ConfigurationValue, ModuleCatalog, ModuleDefinition,
        RuntimeDependencyDescriptor,
    },
    provenance::inspect_project_provenance,
    region::{RegionError, parse_managed_regions, reconcile_managed_region},
    release::ReleaseIdentity,
    render::{
        render_embedded_base_files, render_embedded_project_files, render_managed_dockerfile,
    },
    state::{
        MANAGED_MARKER_VERSION, ManagedRegionRecord, OwnershipKind, OwnershipRecord,
        PROJECT_STATE_PATH, ProjectState, SelectedModule, SelectedProvider, StateError, sha256_hex,
        validate_relative_path,
    },
};

const PLAN_SCHEMA_VERSION: u32 = 1;
const SCHEMA_2_MANAGED_REGIONS: &[(&str, &str)] = &[
    ("Cargo.toml", "framework-dependency"),
    ("apps/service/src/composition.rs", "modules"),
];

/// Filesystem-free inputs to deterministic module planning.
#[derive(Clone, Debug)]
pub struct ProjectSnapshot {
    /// Strict project state.
    pub state: ProjectState,
    /// Exact UTF-8 contents of known project paths. Missing keys mean absent files.
    pub files: BTreeMap<String, String>,
    /// Explicit immutable framework release used by every generated dependency.
    pub release_identity: ReleaseIdentity,
    /// Deterministically rendered compile-time base descriptors.
    pub base_files: BTreeMap<String, String>,
    /// Manifest and Cargo-configuration provenance findings captured from the filesystem.
    pub(crate) provenance_diagnostics: Vec<Diagnostic>,
    /// Exact bytes of the committed Cargo lockfile, stored outside the UTF-8 file map.
    pub lockfile: Option<Vec<u8>>,
}

/// Kind of deterministic management plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanAction {
    /// Add a requested module and transitive dependencies.
    Add,
    /// Remove a module after reverse-dependency checks.
    Remove,
    /// Replace the selected module set with one exact bundled profile closure.
    ProfileSet,
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
        /// Legacy UTF-8 upgraded lockfile contents.
        content: String,
    },
    /// Write exact Cargo-authoritative lockfile bytes while sealing schema-2 lifecycle changes.
    WriteResolvedLock {
        /// Always `Cargo.lock`.
        path: String,
        /// Expected prior lockfile hash.
        expected_hash: String,
        /// Hash of the resolved lockfile.
        content_hash: String,
        /// Exact resolver-returned lockfile bytes.
        content: Vec<u8>,
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
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::CreateFile { path, .. }
            | Self::ReplaceKitFile { path, .. }
            | Self::ReconcileRegions { path, .. }
            | Self::RegenerateDerived { path, .. }
            | Self::RemoveFile { path, .. }
            | Self::WriteLock { path, .. }
            | Self::WriteResolvedLock { path, .. }
            | Self::WriteState { path, .. } => path,
        }
    }

    pub(crate) fn replacement_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::CreateFile { content, .. }
            | Self::ReplaceKitFile { content, .. }
            | Self::ReconcileRegions { content, .. }
            | Self::RegenerateDerived { content, .. }
            | Self::WriteLock { content, .. }
            | Self::WriteState { content, .. } => Some(content.as_bytes()),
            Self::WriteResolvedLock { content, .. } => Some(content),
            Self::RemoveFile { .. } => None,
        }
    }

    pub(crate) fn expected_hash(&self) -> Option<&str> {
        match self {
            Self::CreateFile { .. } => None,
            Self::ReplaceKitFile { expected_hash, .. }
            | Self::ReconcileRegions { expected_hash, .. }
            | Self::RemoveFile { expected_hash, .. }
            | Self::WriteLock { expected_hash, .. }
            | Self::WriteResolvedLock { expected_hash, .. }
            | Self::WriteState { expected_hash, .. } => Some(expected_hash),
            Self::RegenerateDerived { expected_hash, .. } => expected_hash.as_deref(),
        }
    }

    fn content_hash(&self) -> Option<&str> {
        match self {
            Self::CreateFile { content_hash, .. }
            | Self::ReplaceKitFile { content_hash, .. }
            | Self::ReconcileRegions { content_hash, .. }
            | Self::RegenerateDerived { content_hash, .. }
            | Self::WriteLock { content_hash, .. }
            | Self::WriteResolvedLock { content_hash, .. }
            | Self::WriteState { content_hash, .. } => Some(content_hash),
            Self::RemoveFile { .. } => None,
        }
    }

    fn order(&self) -> u8 {
        match self {
            Self::CreateFile { .. } => 0,
            Self::ReplaceKitFile { .. } | Self::ReconcileRegions { .. } => 1,
            Self::RegenerateDerived { .. } => 2,
            Self::RemoveFile { .. } => 3,
            Self::WriteLock { .. } | Self::WriteResolvedLock { .. } => 4,
            Self::WriteState { .. } => 5,
        }
    }
}

/// Reviewable deterministic desired-state plan; application requires a sealed wrapper.
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

/// A Cargo-resolved plan whose exact filesystem inputs and lock bytes are immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedManagementPlan {
    plan: ManagementPlan,
    expected_inputs: BTreeMap<String, String>,
    resolution: Option<CargoResolverResult>,
}

impl SealedManagementPlan {
    /// Returns the reviewable filesystem plan, including exact lock bytes when changed.
    #[must_use]
    pub const fn plan(&self) -> &ManagementPlan {
        &self.plan
    }

    /// Returns the resolver result. Idempotent no-op plans do not run a resolver.
    #[must_use]
    pub const fn resolution(&self) -> Option<&CargoResolverResult> {
        self.resolution.as_ref()
    }

    /// Returns whether applying the sealed plan would change no project file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plan.is_empty()
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

/// Result of a successfully committed sealed plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplyOutcome {
    /// Applied deterministic plan identity.
    pub plan_id: String,
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
    /// Project preflight findings blocked planning or application.
    Preflight(Vec<Diagnostic>),
    /// A plan no longer matches current project bytes.
    StalePlan(String),
    /// A project path or source was unavailable or unsafe.
    InvalidProject(String),
    /// Cargo resolution failed while sealing a staged candidate.
    Resolver(CargoResolverError),
    /// Sibling staging, publication, or sealed-input verification failed.
    Lifecycle(LifecycleError),
    /// Lifecycle lock, recovery, or durable transaction application failed.
    Journal(String),
    /// A filesystem operation failed.
    Filesystem {
        /// Path whose filesystem operation failed.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Deterministic plan identity encoding failed.
    PlanEncoding(serde_json::Error),
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => write!(formatter, "module catalog error: {error}"),
            Self::State(error) => write!(formatter, "project state error: {error}"),
            Self::Region(error) => write!(formatter, "managed region error: {error}"),
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
            Self::Resolver(error) => write!(formatter, "Cargo resolution failed: {error}"),
            Self::Lifecycle(error) => write!(formatter, "lifecycle staging failed: {error}"),
            Self::Journal(error) => {
                write!(formatter, "durable lifecycle transaction failed: {error}")
            }
            Self::Filesystem { path, source } => {
                write!(
                    formatter,
                    "filesystem operation failed for {}: {source}",
                    path.display()
                )
            }
            Self::PlanEncoding(error) => {
                write!(
                    formatter,
                    "cannot encode deterministic plan identity: {error}"
                )
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
            Self::Resolver(error) => Some(error),
            Self::Lifecycle(error) => Some(error),
            Self::Filesystem { source, .. } => Some(source),
            Self::PlanEncoding(error) => Some(error),
            Self::Preflight(_)
            | Self::StalePlan(_)
            | Self::InvalidProject(_)
            | Self::Journal(_) => None,
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

impl From<CargoResolverError> for ManagerError {
    fn from(error: CargoResolverError) -> Self {
        Self::Resolver(error)
    }
}

impl From<LifecycleError> for ManagerError {
    fn from(error: LifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}

/// Filesystem boundary around the pure catalog planner.
pub struct ProjectManager<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) release_identity: &'a ReleaseIdentity,
    pub(crate) catalog: &'a ModuleCatalog,
}

impl<'a> ProjectManager<'a> {
    /// Creates a manager for one project and one explicit immutable framework release.
    #[must_use]
    pub fn new(
        project_root: &'a Path,
        release_identity: &'a ReleaseIdentity,
        catalog: &'a ModuleCatalog,
    ) -> Self {
        Self {
            project_root,
            release_identity,
            catalog,
        }
    }

    /// Computes a filesystem-backed, non-Cargo desired add plan after lifecycle recovery.
    ///
    /// The returned plan is intentionally unsealed and cannot be passed to [`Self::apply`].
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for invalid state, corrupt ownership, conflicts,
    /// missing sources, or unsafe project paths.
    pub fn plan_add(&self, module: &str) -> Result<ManagementPlan, ManagerError> {
        let lifecycle_lock = self.acquire_and_recover()?;
        let snapshot = self.load_snapshot(&lifecycle_lock)?;
        plan_add(self.catalog, &snapshot, module)
    }

    /// Computes a filesystem-backed, non-Cargo desired removal plan after lifecycle recovery.
    ///
    /// The returned plan is intentionally unsealed and cannot be passed to [`Self::apply`].
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for reverse dependents, drift, corruption, or
    /// any other preflight error.
    pub fn plan_remove(&self, module: &str) -> Result<ManagementPlan, ManagerError> {
        let lifecycle_lock = self.acquire_and_recover()?;
        let snapshot = self.load_snapshot(&lifecycle_lock)?;
        plan_remove(self.catalog, &snapshot, module)
    }

    /// Resolves and seals one add plan with the production Cargo resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for planning, staging, or Cargo resolution failures.
    pub fn seal_add(
        &self,
        module: &str,
        offline: bool,
    ) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_add_with(module, offline, &CargoLockfileResolver)
    }

    /// Resolves and seals one add plan with an injected deterministic resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for planning, staging, or resolver failures.
    pub fn seal_add_with<R: LockfileResolver + ?Sized>(
        &self,
        module: &str,
        offline: bool,
        resolver: &R,
    ) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_change(module, offline, resolver, plan_add)
    }

    /// Resolves and seals one removal plan with the production Cargo resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for planning, staging, or Cargo resolution failures.
    pub fn seal_remove(
        &self,
        module: &str,
        offline: bool,
    ) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_remove_with(module, offline, &CargoLockfileResolver)
    }

    /// Resolves and seals one removal plan with an injected deterministic resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for planning, staging, or resolver failures.
    pub fn seal_remove_with<R: LockfileResolver + ?Sized>(
        &self,
        module: &str,
        offline: bool,
        resolver: &R,
    ) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_change(module, offline, resolver, plan_remove)
    }

    /// Computes a filesystem-backed, non-Cargo exact profile transition after recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for an unknown profile or any unsafe preflight.
    pub fn plan_profile_set(&self, profile: &str) -> Result<ManagementPlan, ManagerError> {
        let lifecycle_lock = self.acquire_and_recover()?;
        let snapshot = self.load_snapshot(&lifecycle_lock)?;
        plan_profile_set(self.catalog, &snapshot, profile)
    }

    /// Resolves and seals one exact profile transition with the production Cargo resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for planning, staging, or Cargo resolution failures.
    pub fn seal_profile_set(
        &self,
        profile: &str,
        offline: bool,
    ) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_profile_set_with(profile, offline, &CargoLockfileResolver)
    }

    /// Resolves and seals one exact profile transition with an injected resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for planning, staging, or resolver failures.
    pub fn seal_profile_set_with<R: LockfileResolver + ?Sized>(
        &self,
        profile: &str,
        offline: bool,
        resolver: &R,
    ) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_change(profile, offline, resolver, plan_profile_set)
    }

    /// Produces the deterministic reconciliation diff after recovery, without Cargo.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] when project state cannot be safely inspected.
    pub fn diff(&self) -> Result<ManagementPlan, ManagerError> {
        let lifecycle_lock = self.acquire_and_recover()?;
        let snapshot = self.load_snapshot(&lifecycle_lock)?;
        plan_diff(self.catalog, &snapshot)
    }

    /// Resolves and seals an identity-based project update with the production Cargo resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] for unsupported legacy state, unsafe baselines, provenance,
    /// staging, or Cargo resolution failures.
    pub fn seal_update(&self, offline: bool) -> Result<SealedManagementPlan, ManagerError> {
        self.seal_update_with(offline, &CargoLockfileResolver)
    }

    /// Resolves and seals an identity-based project update with an injected resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] under the same conditions as [`Self::seal_update`].
    pub fn seal_update_with<R: LockfileResolver + ?Sized>(
        &self,
        offline: bool,
        resolver: &R,
    ) -> Result<SealedManagementPlan, ManagerError> {
        let lifecycle_lock = self.acquire_and_recover()?;
        ensure_safe_project_path(self.project_root, PROJECT_STATE_PATH)?;
        let state_source = read_required_file(&self.project_root.join(PROJECT_STATE_PATH))?;
        let schema_version = toml::from_str::<toml::Value>(&state_source)
            .map_err(|error| ManagerError::InvalidProject(error.to_string()))?
            .get("schema_version")
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| {
                ManagerError::InvalidProject(
                    "project state is missing integer `schema_version`".to_owned(),
                )
            })?;
        let (snapshot, plan, legacy_cutover) = match schema_version {
            1 => {
                let snapshot = crate::upgrade::load_legacy_snapshot(
                    self.project_root,
                    self.release_identity,
                    self.catalog,
                )?;
                let plan = crate::upgrade::plan_upgrade(
                    self.catalog,
                    &snapshot,
                    self.release_identity.version(),
                )?;
                (snapshot, plan, true)
            }
            2 => {
                let snapshot = self.load_snapshot(&lifecycle_lock)?;
                let plan = plan(self.catalog, &snapshot, PlanAction::Upgrade, None)?;
                (snapshot, plan, false)
            }
            other => {
                return Err(ManagerError::InvalidProject(format!(
                    "unsupported project state schema version {other}"
                )));
            }
        };
        self.seal_update_plan(&snapshot, plan, legacy_cutover, offline, resolver)
    }

    /// Diagnoses state, dependency closure, catalog versions, owned files, and
    /// managed markers after recovering any incomplete transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] only when recovery or project inspection fails.
    pub fn doctor(&self) -> Result<DoctorReport, ManagerError> {
        let lifecycle_lock = self.acquire_and_recover()?;
        let snapshot = self.load_snapshot(&lifecycle_lock)?;
        Ok(doctor(self.catalog, &snapshot))
    }

    /// Applies only a previously Cargo-resolved sealed plan through the durable journal.
    ///
    /// This path performs no planning and cannot invoke Cargo. State remains the final
    /// journal operation.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] before writes when any sealed input is stale, or when
    /// lifecycle recovery, journal preparation, or journal application fails.
    pub fn apply(&self, sealed: &SealedManagementPlan) -> Result<ApplyOutcome, ManagerError> {
        let mut lifecycle_lock = self.acquire_and_recover()?;
        if sealed.is_empty() {
            return Ok(ApplyOutcome {
                plan_id: sealed.plan.plan_id.clone(),
                changed_files: 0,
            });
        }
        verify_project_inputs(self.project_root, &sealed.expected_inputs)
            .map_err(|error| ManagerError::StalePlan(error.to_string()))?;
        let operations = sealed
            .plan
            .operations
            .iter()
            .map(journal_operation)
            .collect::<Result<Vec<_>, _>>()?;
        lifecycle_lock
            .prepare_transaction(sealed.plan.plan_id.clone(), operations)
            .map_err(|error| ManagerError::Journal(error.to_string()))?
            .apply()
            .map_err(|error| ManagerError::Journal(error.to_string()))?;
        Ok(ApplyOutcome {
            plan_id: sealed.plan.plan_id.clone(),
            changed_files: sealed.plan.operations.len(),
        })
    }

    fn seal_change<R, F>(
        &self,
        module: &str,
        offline: bool,
        resolver: &R,
        planner: F,
    ) -> Result<SealedManagementPlan, ManagerError>
    where
        R: LockfileResolver + ?Sized,
        F: FnOnce(&ModuleCatalog, &ProjectSnapshot, &str) -> Result<ManagementPlan, ManagerError>,
    {
        let lifecycle_lock = self.acquire_and_recover()?;
        let snapshot = self.load_snapshot(&lifecycle_lock)?;
        let current_lockfile = snapshot.lockfile.as_deref().ok_or_else(|| {
            ManagerError::InvalidProject(
                "schema-2 lifecycle mutation requires a committed Cargo.lock".to_owned(),
            )
        })?;
        if snapshot.state.ownership_of("Cargo.lock") != Some(OwnershipKind::DependencyLock) {
            return Err(ManagerError::InvalidProject(
                "schema-2 lifecycle mutation requires dependency-lock ownership for Cargo.lock"
                    .to_owned(),
            ));
        }
        let mut plan = planner(self.catalog, &snapshot, module)?;
        let stages = ExistingProjectStages::create(self.project_root)?;
        if plan.is_empty() {
            identify_management_plan(&mut plan, stages.expected_inputs())?;
            return Ok(SealedManagementPlan {
                plan,
                expected_inputs: stages.expected_inputs().clone(),
                resolution: None,
            });
        }

        let state_index = plan
            .operations
            .iter()
            .position(|operation| matches!(operation, PlanOperation::WriteState { .. }))
            .ok_or_else(|| {
                ManagerError::InvalidProject(
                    "nonempty schema-2 lifecycle plan must commit state last".to_owned(),
                )
            })?;
        let state_operation = plan.operations.remove(state_index);
        for operation in &plan.operations {
            match operation {
                PlanOperation::WriteLock { .. }
                | PlanOperation::WriteResolvedLock { .. }
                | PlanOperation::WriteState { .. } => {
                    return Err(ManagerError::InvalidProject(
                        "pure schema-2 planning unexpectedly emitted a lock or duplicate state write"
                            .to_owned(),
                    ));
                }
                PlanOperation::RemoveFile { path, .. } => {
                    remove_project_file(stages.candidate(), path)?;
                }
                _ => {
                    let replacement = operation.replacement_bytes().ok_or_else(|| {
                        ManagerError::InvalidProject(format!(
                            "plan operation for `{}` has no replacement bytes",
                            operation.path()
                        ))
                    })?;
                    write_project_file(stages.candidate(), operation.path(), replacement)?;
                }
            }
        }

        let request = CargoResolverRequest::update_locked(
            stages.current(),
            stages.candidate(),
            snapshot.state.framework.clone(),
            offline,
        );
        let resolution = resolver.resolve(&request)?;
        let resolved_lockfile = resolution.lockfile();
        write_project_file(stages.candidate(), "Cargo.lock", resolved_lockfile)?;
        if resolved_lockfile != current_lockfile {
            plan.operations.push(PlanOperation::WriteResolvedLock {
                path: "Cargo.lock".to_owned(),
                expected_hash: sha256_hex(current_lockfile),
                content_hash: sha256_hex(resolved_lockfile),
                content: resolved_lockfile.to_vec(),
            });
        }
        let state_bytes = state_operation.replacement_bytes().ok_or_else(|| {
            ManagerError::InvalidProject("state operation has no replacement bytes".to_owned())
        })?;
        write_project_file(stages.candidate(), PROJECT_STATE_PATH, state_bytes)?;
        plan.operations.push(state_operation);
        identify_management_plan(&mut plan, stages.expected_inputs())?;
        Ok(SealedManagementPlan {
            plan,
            expected_inputs: stages.expected_inputs().clone(),
            resolution: Some(resolution),
        })
    }

    fn acquire_and_recover(&self) -> Result<LifecycleLock, ManagerError> {
        let lifecycle_lock = LifecycleLock::acquire(self.project_root)
            .map_err(|error| ManagerError::Journal(error.to_string()))?;
        lifecycle_lock
            .recover()
            .map_err(|error| ManagerError::Journal(error.to_string()))?;
        Ok(lifecycle_lock)
    }
    fn seal_update_plan<R: LockfileResolver + ?Sized>(
        &self,
        snapshot: &ProjectSnapshot,
        mut plan: ManagementPlan,
        legacy_cutover: bool,
        offline: bool,
        resolver: &R,
    ) -> Result<SealedManagementPlan, ManagerError> {
        let current_lockfile = snapshot.lockfile.as_deref().ok_or_else(|| {
            ManagerError::InvalidProject(
                "project update requires a committed Cargo.lock".to_owned(),
            )
        })?;
        let stages = ExistingProjectStages::create(self.project_root)?;
        if plan.is_empty() {
            identify_management_plan(&mut plan, stages.expected_inputs())?;
            return Ok(SealedManagementPlan {
                plan,
                expected_inputs: stages.expected_inputs().clone(),
                resolution: None,
            });
        }
        let state_operation = stage_update_operations(stages.candidate(), &mut plan)?;
        let state_bytes = state_operation.replacement_bytes().ok_or_else(|| {
            ManagerError::InvalidProject("state operation has no replacement bytes".to_owned())
        })?;
        validate_update_candidate(stages.candidate(), self.release_identity, state_bytes)?;
        let request = if legacy_cutover {
            CargoResolverRequest::legacy_cutover(
                stages.current(),
                stages.candidate(),
                self.release_identity.clone(),
                offline,
            )
        } else {
            CargoResolverRequest::revision_precise(
                stages.current(),
                stages.candidate(),
                snapshot.state.framework.clone(),
                self.release_identity.clone(),
                offline,
            )
        };
        let resolution = resolver.resolve(&request)?;
        let resolved_lockfile = resolution.lockfile();
        write_project_file(stages.candidate(), "Cargo.lock", resolved_lockfile)?;
        if resolved_lockfile != current_lockfile {
            plan.operations.push(PlanOperation::WriteResolvedLock {
                path: "Cargo.lock".to_owned(),
                expected_hash: sha256_hex(current_lockfile),
                content_hash: sha256_hex(resolved_lockfile),
                content: resolved_lockfile.to_vec(),
            });
        }
        write_project_file(stages.candidate(), PROJECT_STATE_PATH, state_bytes)?;
        plan.operations.push(state_operation);
        identify_management_plan(&mut plan, stages.expected_inputs())?;
        Ok(SealedManagementPlan {
            plan,
            expected_inputs: stages.expected_inputs().clone(),
            resolution: Some(resolution),
        })
    }

    fn load_snapshot(
        &self,
        _lifecycle_lock: &LifecycleLock,
    ) -> Result<ProjectSnapshot, ManagerError> {
        validate_application_template_catalog(self.catalog)
            .map_err(ManagerError::InvalidProject)?;
        ensure_safe_project_path(self.project_root, PROJECT_STATE_PATH)?;
        let state_path = self.project_root.join(PROJECT_STATE_PATH);
        let state_source = read_required_file(&state_path)?;
        if toml::from_str::<toml::Value>(&state_source)
            .ok()
            .and_then(|state| {
                state
                    .get("schema_version")
                    .and_then(toml::Value::as_integer)
            })
            == Some(1)
        {
            return Err(ManagerError::InvalidProject(
                "legacy schema-1 project; run `cargo service update`".to_owned(),
            ));
        }
        let state = ProjectState::parse(&state_source)?;
        let identity_matches = state.framework == *self.release_identity;
        let base_files = if identity_matches {
            render_embedded_base_files(&state.service, &state.profile.id, self.release_identity)
                .map_err(|error| ManagerError::InvalidProject(error.to_string()))?
        } else {
            BTreeMap::new()
        };
        let runtime_features = state
            .modules
            .iter()
            .map(|module| module.id.clone())
            .collect::<Vec<_>>();
        let provenance =
            inspect_project_provenance(self.project_root, &state.framework, &runtime_features)
                .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;

        let mut paths = BTreeSet::new();
        paths.insert(PROJECT_STATE_PATH.to_owned());
        paths.extend(state.ownership.iter().map(|record| record.path.clone()));
        paths.extend(
            state
                .managed_regions
                .iter()
                .map(|region| region.path.clone()),
        );
        paths.extend(base_files.keys().cloned());
        paths.extend(
            APPLICATION_TEMPLATE_DESCRIPTORS
                .iter()
                .map(|descriptor| descriptor.path.to_owned()),
        );
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
        paths.remove("Cargo.lock");

        let mut files = provenance.manifest_files;
        for path in &paths {
            validate_relative_path(path)?;
            ensure_safe_project_path(self.project_root, path)?;
            let absolute = self.project_root.join(path);
            if let Some(contents) = read_optional_file(&absolute)? {
                files.insert(path.clone(), contents);
            }
        }
        let lockfile = read_regular_bytes(&self.project_root.join("Cargo.lock"))?;
        if let Some(contents) = lockfile
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        {
            files.insert("Cargo.lock".to_owned(), contents.to_owned());
        }
        Ok(ProjectSnapshot {
            state,
            files,
            release_identity: self.release_identity.clone(),
            base_files,
            provenance_diagnostics: provenance
                .findings
                .into_iter()
                .map(|finding| diagnostic(finding.code, Some(&finding.path), finding.message))
                .collect(),
            lockfile,
        })
    }
}

fn stage_update_operations(
    candidate: &Path,
    plan: &mut ManagementPlan,
) -> Result<PlanOperation, ManagerError> {
    let state_index = plan
        .operations
        .iter()
        .position(|operation| matches!(operation, PlanOperation::WriteState { .. }))
        .ok_or_else(|| {
            ManagerError::InvalidProject(
                "nonempty project update must commit schema-2 state last".to_owned(),
            )
        })?;
    let state_operation = plan.operations.remove(state_index);
    for operation in &plan.operations {
        match operation {
            PlanOperation::WriteLock { .. }
            | PlanOperation::WriteResolvedLock { .. }
            | PlanOperation::WriteState { .. } => {
                return Err(ManagerError::InvalidProject(
                    "pure project update unexpectedly emitted a lock or duplicate state write"
                        .to_owned(),
                ));
            }
            PlanOperation::RemoveFile { path, .. } => {
                remove_project_file(candidate, path)?;
            }
            _ => {
                let replacement = operation.replacement_bytes().ok_or_else(|| {
                    ManagerError::InvalidProject(format!(
                        "update operation for `{}` has no replacement bytes",
                        operation.path()
                    ))
                })?;
                write_project_file(candidate, operation.path(), replacement)?;
            }
        }
    }
    prune_empty_legacy_directories(candidate)?;
    ensure_thin_candidate_tree(candidate)?;
    Ok(state_operation)
}

fn validate_update_candidate(
    candidate: &Path,
    release_identity: &ReleaseIdentity,
    state_bytes: &[u8],
) -> Result<(), ManagerError> {
    let next_state = ProjectState::parse(std::str::from_utf8(state_bytes).map_err(|_| {
        ManagerError::InvalidProject("state operation is not valid UTF-8".to_owned())
    })?)?;
    let runtime_features = next_state
        .modules
        .iter()
        .map(|module| module.id.clone())
        .collect::<Vec<_>>();
    let provenance = inspect_project_provenance(candidate, release_identity, &runtime_features)
        .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    if provenance.findings.is_empty() {
        return Ok(());
    }
    Err(ManagerError::Preflight(
        provenance
            .findings
            .into_iter()
            .map(|finding| diagnostic(finding.code, Some(&finding.path), finding.message))
            .collect(),
    ))
}

fn prune_empty_legacy_directories(project_root: &Path) -> Result<(), ManagerError> {
    for relative in [".sqlx", "specs", "templates", "xtask", "crates"] {
        let _ = prune_empty_directory(&project_root.join(relative))?;
    }
    Ok(())
}

fn prune_empty_directory(directory: &Path) -> Result<bool, ManagerError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(source) => {
            return Err(ManagerError::Filesystem {
                path: directory.to_owned(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(false);
    }
    let entries = fs::read_dir(directory)
        .map_err(|source| ManagerError::Filesystem {
            path: directory.to_owned(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ManagerError::Filesystem {
            path: directory.to_owned(),
            source,
        })?;
    let mut empty = true;
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ManagerError::Filesystem {
            path: path.clone(),
            source,
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() && prune_empty_directory(&path)?
        {
            continue;
        }
        empty = false;
    }
    if empty {
        fs::remove_dir(directory).map_err(|source| ManagerError::Filesystem {
            path: directory.to_owned(),
            source,
        })?;
    }
    Ok(empty)
}

fn ensure_thin_candidate_tree(project_root: &Path) -> Result<(), ManagerError> {
    for forbidden in [".sqlx", "specs", "templates", "xtask"] {
        let path = project_root.join(forbidden);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(ManagerError::InvalidProject(format!(
                    "legacy path `{forbidden}` is forbidden in a thin service; relocate application-owned bytes before update"
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ManagerError::Filesystem {
                    path,
                    source: error,
                });
            }
        }
    }
    inspect_candidate_crates(project_root, &project_root.join("crates"))?;
    inspect_candidate_migrations(project_root)?;
    Ok(())
}

fn inspect_candidate_crates(project_root: &Path, directory: &Path) -> Result<(), ManagerError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ManagerError::Filesystem {
                path: directory.to_owned(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ManagerError::InvalidProject(format!(
            "thin-service crate root `{}` must be a regular directory",
            directory.display()
        )));
    }
    let at_crates_root = directory
        .strip_prefix(project_root)
        .is_ok_and(|relative| relative == Path::new("crates"));
    for entry in fs::read_dir(directory).map_err(|source| ManagerError::Filesystem {
        path: directory.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| ManagerError::Filesystem {
            path: directory.to_owned(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ManagerError::Filesystem {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ManagerError::InvalidProject(format!(
                "thin-service candidate refuses symlink `{}`",
                path.display()
            )));
        }
        if at_crates_root
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == "service-kit" || name.starts_with("omnius-"))
        {
            return Err(ManagerError::InvalidProject(format!(
                "legacy framework crate directory `{}` is forbidden in a thin service; relocate application-owned bytes before update",
                path.display()
            )));
        }
        if metadata.is_dir() {
            inspect_candidate_crates(project_root, &path)?;
            continue;
        }
        if !metadata.is_file() || entry.file_name() != OsStr::new("Cargo.toml") {
            continue;
        }
        let source = read_required_file(&path)?;
        let document = toml::from_str::<toml::Value>(&source).map_err(|error| {
            ManagerError::InvalidProject(format!(
                "candidate crate manifest `{}` is invalid TOML: {error}",
                path.display()
            ))
        })?;
        let package_name = document
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str);
        let relative = path
            .strip_prefix(project_root)
            .unwrap_or(path.as_path())
            .to_string_lossy();
        if relative.starts_with("crates/service-kit/")
            || package_name.is_some_and(|name| name.starts_with("omnius-"))
        {
            return Err(ManagerError::InvalidProject(format!(
                "legacy framework crate `{relative}` is forbidden in a thin service; relocate application-owned bytes before update"
            )));
        }
    }
    Ok(())
}

fn inspect_candidate_migrations(project_root: &Path) -> Result<(), ManagerError> {
    let directory = project_root.join("migrations");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ManagerError::Filesystem {
                path: directory,
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| ManagerError::Filesystem {
            path: directory.clone(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ManagerError::Filesystem {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ManagerError::InvalidProject(format!(
                "migration path `{}` must be a regular file in the application migration root",
                path.display()
            )));
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            ManagerError::InvalidProject("migration filenames must be UTF-8".to_owned())
        })?;
        if name == "application-compatibility.toml" {
            continue;
        }
        let version = name
            .strip_suffix(".sql")
            .and_then(|stem| stem.split_once('_'))
            .and_then(|(version, description)| {
                (!description.is_empty())
                    .then(|| version.parse::<u64>().ok())
                    .flatten()
            });
        if !version.is_some_and(|version| {
            (9_000_000_000_000_000_000..=9_099_999_999_999_999_999).contains(&version)
        }) {
            return Err(ManagerError::InvalidProject(format!(
                "legacy framework migration `migrations/{name}` is forbidden in a thin service; relocate application SQL into the reserved application range before update"
            )));
        }
    }
    Ok(())
}

fn journal_operation(operation: &PlanOperation) -> Result<JournalOperation, ManagerError> {
    let path = operation.path().to_owned();
    if let Some(replacement) = operation.replacement_bytes() {
        let content_hash = operation.content_hash().ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "write operation for `{path}` is missing its sealed output hash"
            ))
        })?;
        JournalOperation::write(
            path,
            operation.expected_hash().map(str::to_owned),
            replacement.to_vec(),
            content_hash.to_owned(),
        )
        .map_err(|error| ManagerError::Journal(error.to_string()))
    } else {
        let expected_hash = operation.expected_hash().ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "remove operation for `{path}` is missing its sealed input hash"
            ))
        })?;
        JournalOperation::remove(path, expected_hash.to_owned())
            .map_err(|error| ManagerError::Journal(error.to_string()))
    }
}

pub(crate) fn compose_initial_profile(
    catalog: &ModuleCatalog,
    release_identity: &ReleaseIdentity,
    state: ProjectState,
    mut files: BTreeMap<String, String>,
    base_files: BTreeMap<String, String>,
) -> Result<(ProjectState, BTreeMap<String, String>), ManagerError> {
    validate_application_template_catalog(catalog).map_err(ManagerError::InvalidProject)?;
    let snapshot = ProjectSnapshot {
        state: state.clone(),
        files: files.clone(),
        release_identity: release_identity.clone(),
        base_files,
        provenance_diagnostics: Vec::new(),
        lockfile: None,
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
    append_state_operation(&snapshot, &mut next_state, &mut operations)?;
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
            PlanOperation::WriteResolvedLock { .. } => {
                return Err(ManagerError::InvalidProject(
                    "initial profile composition unexpectedly emitted resolved lock bytes"
                        .to_owned(),
                ));
            }
        }
    }
    let state_source = files.get(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject("initial profile composition removed project state".to_owned())
    })?;
    let final_state = ProjectState::parse(state_source)?;
    Ok((final_state, files))
}

/// Non-filesystem add planning from a caller-supplied immutable snapshot.
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

/// Non-filesystem remove planning from a caller-supplied immutable snapshot.
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

/// Non-filesystem exact profile planning from a caller-supplied immutable snapshot.
///
/// # Errors
///
/// Returns [`ManagerError`] for an unknown profile or any unsafe preflight.
pub fn plan_profile_set(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    profile: &str,
) -> Result<ManagementPlan, ManagerError> {
    plan(catalog, snapshot, PlanAction::ProfileSet, Some(profile))
}

/// Non-filesystem reconciliation planning from a caller-supplied immutable snapshot.
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
    let mut diagnostics = diagnose_snapshot(catalog, snapshot);
    if matches!(action, PlanAction::Diff | PlanAction::Upgrade)
        && snapshot.state.framework != snapshot.release_identity
    {
        diagnostics.retain(|diagnostic| diagnostic.code != "release-mismatch");
        if action == PlanAction::Diff && diagnostics.is_empty() {
            return finish_plan(
                PlanAction::Diff,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
        }
    }
    if !diagnostics.is_empty() {
        return Err(ManagerError::Preflight(diagnostics));
    }
    let selection = resolve_selection(catalog, &snapshot.state, action, requested)?;
    if matches!(action, PlanAction::Add | PlanAction::Remove)
        && selection.added.is_empty()
        && selection.removed.is_empty()
    {
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
    append_state_operation(snapshot, &mut next_state, &mut operations)?;
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
        (PlanAction::Add, Some(module_or_profile)) => {
            resolve_add_request(catalog, &before, module_or_profile)?
        }
        (PlanAction::Remove, Some(module_or_profile)) => {
            resolve_remove_request(catalog, state, &before, module_or_profile)?
        }
        (PlanAction::ProfileSet, Some(profile)) => {
            let profiles = ProfileCatalog::bundled()
                .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
            profiles
                .resolve(profile, catalog)
                .map_err(|error| ManagerError::InvalidProject(error.to_string()))?
                .modules()
                .iter()
                .cloned()
                .collect()
        }
        (PlanAction::Upgrade | PlanAction::Diff, None) => before.clone(),
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

fn resolve_add_request(
    catalog: &ModuleCatalog,
    before: &BTreeSet<String>,
    requested: &str,
) -> Result<BTreeSet<String>, ManagerError> {
    if catalog.module(requested).is_some() {
        return Ok(catalog.resolve_add(before, requested)?);
    }
    let profiles = ProfileCatalog::bundled()
        .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    if !profiles
        .profiles()
        .iter()
        .any(|profile| profile.id == requested)
    {
        return Ok(catalog.resolve_add(before, requested)?);
    }
    let profile = profiles
        .resolve(requested, catalog)
        .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    let mut after = before.clone();
    for module in profile.modules() {
        after = catalog.resolve_add(&after, module)?;
    }
    Ok(after)
}

fn resolve_remove_request(
    catalog: &ModuleCatalog,
    state: &ProjectState,
    before: &BTreeSet<String>,
    requested: &str,
) -> Result<BTreeSet<String>, ManagerError> {
    if catalog.module(requested).is_some() {
        return Ok(catalog.resolve_remove(before, requested)?);
    }
    let profiles = ProfileCatalog::bundled()
        .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    let Some(profile) = profiles
        .profiles()
        .iter()
        .find(|profile| profile.id == requested)
    else {
        return Ok(catalog.resolve_remove(before, requested)?);
    };
    let mut after = before.clone();
    for module in &profile.modules {
        if state.profile.id == requested || state.profile.additions.contains(module) {
            after.remove(module);
        }
    }
    catalog.validate_selection(&after)?;
    Ok(after)
}

fn build_next_state(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    action: PlanAction,
    requested: Option<&str>,
    selection: &SelectionChange,
) -> Result<ProjectState, ManagerError> {
    let mut next_state = snapshot.state.clone();
    next_state.modules = catalog
        .composition_order(&selection.after)?
        .into_iter()
        .map(|definition| SelectedModule {
            id: definition.id.clone(),
            version: definition.version.clone(),
        })
        .collect();
    retain_selected_compose_volumes(&mut next_state, catalog)?;
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
    if snapshot.state.framework != snapshot.release_identity {
        plan_release_base_files(snapshot, next_state, &mut operations)?;
    }
    plan_application_templates(
        catalog,
        snapshot,
        &selection.added,
        &selection.removed,
        next_state,
        &mut operations,
        &mut preserved,
    )?;
    let after = selected_ids(next_state);
    catalog.validate_selection(&after)?;
    plan_regions(
        catalog,
        snapshot,
        &selection.before,
        &after,
        next_state,
        &mut operations,
    )?;
    plan_derived(
        catalog,
        snapshot,
        &selection.before,
        &after,
        next_state,
        &mut operations,
    )?;
    Ok((operations, preserved.into_iter().collect()))
}

fn plan_release_base_files(
    snapshot: &ProjectSnapshot,
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    let (target_state, target_files) = render_target_project(snapshot)?;
    let target_kit_owned = target_state
        .ownership
        .iter()
        .filter(|record| record.kind == OwnershipKind::KitOwned)
        .map(|record| (record.path.as_str(), record))
        .collect::<BTreeMap<_, _>>();

    for current_record in snapshot
        .state
        .ownership
        .iter()
        .filter(|record| record.kind == OwnershipKind::KitOwned)
    {
        if let Some(target_record) = target_state
            .ownership
            .iter()
            .find(|record| record.path == current_record.path)
            && target_record.kind != OwnershipKind::KitOwned
        {
            return Err(ManagerError::InvalidProject(format!(
                "revision update cannot change kit-owned file `{}` to {:?} ownership",
                current_record.path, target_record.kind
            )));
        }
        if target_kit_owned.contains_key(current_record.path.as_str()) {
            continue;
        }
        let current = approved_kit_file(snapshot, current_record)?;
        operations.push(PlanOperation::RemoveFile {
            path: current_record.path.clone(),
            expected_hash: sha256_hex(current.as_bytes()),
        });
    }

    for target_record in target_kit_owned.values() {
        let desired = target_files.get(&target_record.path).ok_or_else(|| {
            ManagerError::InvalidProject(format!(
                "target ownership references missing kit-owned file `{}`",
                target_record.path
            ))
        })?;
        let desired_hash = sha256_hex(desired.as_bytes());
        if target_record.approved_sha256.as_deref() != Some(desired_hash.as_str()) {
            return Err(ManagerError::InvalidProject(format!(
                "target renderer approved the wrong hash for kit-owned file `{}`",
                target_record.path
            )));
        }

        match snapshot
            .state
            .ownership
            .iter()
            .find(|record| record.path == target_record.path)
        {
            Some(current_record) if current_record.kind == OwnershipKind::KitOwned => {
                let current = approved_kit_file(snapshot, current_record)?;
                if current != desired {
                    operations.push(PlanOperation::ReplaceKitFile {
                        path: target_record.path.clone(),
                        expected_hash: sha256_hex(current.as_bytes()),
                        content_hash: desired_hash,
                        content: desired.clone(),
                    });
                }
            }
            Some(current_record) => {
                return Err(ManagerError::InvalidProject(format!(
                    "revision update cannot replace {:?} file `{}` with a kit-owned file",
                    current_record.kind, target_record.path
                )));
            }
            None if snapshot.files.contains_key(&target_record.path) => {
                return Err(ManagerError::InvalidProject(format!(
                    "revision update cannot claim unowned file `{}`",
                    target_record.path
                )));
            }
            None => operations.push(PlanOperation::CreateFile {
                path: target_record.path.clone(),
                content_hash: desired_hash,
                content: desired.clone(),
            }),
        }
    }

    next_state
        .ownership
        .retain(|record| record.kind != OwnershipKind::KitOwned);
    next_state
        .ownership
        .extend(target_kit_owned.values().map(|record| (*record).clone()));
    Ok(())
}

fn render_target_project(
    snapshot: &ProjectSnapshot,
) -> Result<(ProjectState, BTreeMap<String, String>), ManagerError> {
    let mut target_files = render_embedded_project_files(
        &snapshot.state.service,
        &snapshot.state.profile.id,
        &snapshot.release_identity,
    )
    .map_err(|error| ManagerError::InvalidProject(error.to_string()))?;
    let target_state_source = target_files.remove(PROJECT_STATE_PATH).ok_or_else(|| {
        ManagerError::InvalidProject(
            "target renderer omitted project state during revision update".to_owned(),
        )
    })?;
    Ok((ProjectState::parse(&target_state_source)?, target_files))
}

fn approved_kit_file<'a>(
    snapshot: &'a ProjectSnapshot,
    record: &OwnershipRecord,
) -> Result<&'a str, ManagerError> {
    let contents = snapshot.files.get(&record.path).ok_or_else(|| {
        ManagerError::InvalidProject(format!("owned kit file `{}` is missing", record.path))
    })?;
    let actual_hash = sha256_hex(contents.as_bytes());
    if record.approved_sha256.as_deref() != Some(actual_hash.as_str()) {
        return Err(ManagerError::InvalidProject(format!(
            "refusing edited kit-owned file `{}` during revision update",
            record.path
        )));
    }
    Ok(contents)
}

fn append_state_operation(
    snapshot: &ProjectSnapshot,
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
) -> Result<(), ManagerError> {
    normalize_next_state(next_state, &snapshot.release_identity);
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

pub(crate) fn normalize_next_state(state: &mut ProjectState, framework: &ReleaseIdentity) {
    state.framework = framework.clone();
    state.profile.additions.sort();
    state.profile.additions.dedup();
    state.profile.removals.sort();
    state.profile.removals.dedup();
    state.retained_compose_volumes.sort();
    state.retained_compose_volumes.dedup();
    state.ownership.sort();
    state.ownership.dedup();
    state.managed_regions.sort();
    state.managed_regions.dedup();
}

pub(crate) fn retain_selected_compose_volumes(
    state: &mut ProjectState,
    catalog: &ModuleCatalog,
) -> Result<(), ManagerError> {
    let selected = selected_ids(state);
    for dependency in catalog.selected_runtime_dependencies(&selected)? {
        if let RuntimeDependencyDescriptor::Compose { volume, .. } = dependency
            && !state.retained_compose_volumes.contains(volume)
        {
            state.retained_compose_volumes.push(volume.clone());
        }
    }
    Ok(())
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
    identify_management_plan(&mut plan, &BTreeMap::new())?;
    Ok(plan)
}

fn identify_management_plan(
    plan: &mut ManagementPlan,
    expected_inputs: &BTreeMap<String, String>,
) -> Result<(), ManagerError> {
    plan.plan_id.clear();
    let bytes =
        serde_json::to_vec(&(&*plan, expected_inputs)).map_err(ManagerError::PlanEncoding)?;
    plan.plan_id = sha256_hex(&bytes);
    Ok(())
}

fn plan_application_templates(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    added: &[String],
    removed: &[String],
    next_state: &mut ProjectState,
    operations: &mut Vec<PlanOperation>,
    preserved: &mut BTreeSet<String>,
) -> Result<(), ManagerError> {
    for id in added {
        let module = required_module(catalog, id)?;
        for path in &module.application_templates {
            let descriptor = application_template(id, path).ok_or_else(|| {
                ManagerError::InvalidProject(format!(
                    "module `{id}` application template `{path}` has no embedded descriptor"
                ))
            })?;
            match (snapshot.files.get(path), snapshot.state.ownership_of(path)) {
                (Some(_), None | Some(OwnershipKind::ApplicationOwned)) => {}
                (Some(_), Some(kind)) => {
                    return Err(ManagerError::InvalidProject(format!(
                        "application template target `{path}` is already owned as {kind:?}"
                    )));
                }
                (None, Some(_)) => {
                    return Err(ManagerError::InvalidProject(format!(
                        "owned application template target `{path}` is missing"
                    )));
                }
                (None, None) => operations.push(PlanOperation::CreateFile {
                    path: path.clone(),
                    content_hash: sha256_hex(descriptor.source.as_bytes()),
                    content: descriptor.source.to_owned(),
                }),
            }
            if next_state.ownership_of(path).is_none() {
                next_state.ownership.push(OwnershipRecord {
                    path: path.clone(),
                    kind: OwnershipKind::ApplicationOwned,
                    approved_sha256: None,
                });
            }
        }
    }

    for id in removed {
        let module = required_module(catalog, id)?;
        preserved.extend(module.persistence.iter().cloned());
        preserved.extend(
            module
                .application_templates
                .iter()
                .filter(|path| snapshot.files.contains_key(path.as_str()))
                .cloned(),
        );
    }
    if !removed.is_empty() {
        preserved.extend(
            snapshot
                .state
                .ownership
                .iter()
                .filter(|record| preserves_historical_path(&record.path))
                .map(|record| record.path.clone()),
        );
    }
    Ok(())
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
            let desired = render_region(catalog, region_id, after, snapshot)?;
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
        update_approved_hash(next_state, &path, &reconciled);
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
    let before_paths = selected_derived_paths(catalog, before)?;
    let after_paths = selected_derived_paths(catalog, after)?;
    for path in before_paths.union(&after_paths) {
        let path = path.clone();
        if !after_paths.contains(&path) {
            let Some(current) = snapshot.files.get(&path) else {
                if snapshot.state.ownership_of(&path).is_some() {
                    return Err(ManagerError::InvalidProject(format!(
                        "owned derived file `{path}` is missing"
                    )));
                }
                continue;
            };
            if snapshot.state.ownership_of(&path) != Some(OwnershipKind::Derived) {
                return Err(ManagerError::InvalidProject(format!(
                    "refusing to remove non-derived file `{path}`"
                )));
            }
            let baseline = render_managed_derived(&path, catalog, before, snapshot)?;
            if current != &baseline {
                return Err(ManagerError::InvalidProject(format!(
                    "refusing edited derived file `{path}`; run doctor before retrying"
                )));
            }
            operations.push(PlanOperation::RemoveFile {
                path: path.clone(),
                expected_hash: sha256_hex(current.as_bytes()),
            });
            next_state.ownership.retain(|record| record.path != path);
            continue;
        }

        let desired = render_managed_derived(&path, catalog, after, snapshot)?;
        let migrated_legacy_ownership = snapshot.files.get(&path).is_some_and(|current| {
            migrate_legacy_react_index_ownership(snapshot, next_state, &path, current)
        });
        if !migrated_legacy_ownership {
            reject_application_owned(&snapshot.state, &path)?;
        }
        if let Some(current) = snapshot.files.get(&path) {
            if snapshot.state.ownership_of(&path) != Some(OwnershipKind::Derived)
                && !migrated_legacy_ownership
            {
                return Err(ManagerError::InvalidProject(format!(
                    "refusing to regenerate non-derived file `{path}`"
                )));
            }
            if before_paths.contains(&path) && !migrated_legacy_ownership {
                let baseline = render_managed_derived(&path, catalog, before, snapshot)?;
                if current != &baseline {
                    return Err(ManagerError::InvalidProject(format!(
                        "refusing edited derived file `{path}`; run doctor before retrying"
                    )));
                }
            }
            if current != &desired {
                update_approved_hash(next_state, &path, &desired);
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
        let approved_sha256 = sha256_hex(desired.as_bytes());
        operations.push(PlanOperation::RegenerateDerived {
            path: path.clone(),
            expected_hash: None,
            content_hash: approved_sha256.clone(),
            content: desired,
        });
        next_state.ownership.push(OwnershipRecord {
            path,
            kind: OwnershipKind::Derived,
            approved_sha256: Some(approved_sha256),
        });
    }
    Ok(())
}

fn migrate_legacy_react_index_ownership(
    snapshot: &ProjectSnapshot,
    next_state: &mut ProjectState,
    path: &str,
    current: &str,
) -> bool {
    if !is_migratable_legacy_react_index(snapshot, path, current) {
        return false;
    }
    let Some(record) = next_state
        .ownership
        .iter_mut()
        .find(|record| record.path == path)
    else {
        return false;
    };
    record.kind = OwnershipKind::Derived;
    record.approved_sha256 = Some(sha256_hex(current.as_bytes()));
    true
}

fn is_migratable_legacy_react_index(snapshot: &ProjectSnapshot, path: &str, current: &str) -> bool {
    path == REACT_INDEX_PATH
        && snapshot.state.framework != snapshot.release_identity
        && snapshot.state.ownership_of(path) == Some(OwnershipKind::ApplicationOwned)
        && current == LEGACY_APPLICATION_REACT_INDEX
}

fn update_approved_hash(state: &mut ProjectState, path: &str, contents: &str) {
    if let Some(record) = state
        .ownership
        .iter_mut()
        .find(|record| record.path == path)
        && matches!(
            record.kind,
            OwnershipKind::KitOwned | OwnershipKind::Derived
        )
    {
        record.approved_sha256 = Some(sha256_hex(contents.as_bytes()));
    }
}

pub(crate) fn selected_derived_paths(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ManagerError> {
    let mut paths = UNCONDITIONAL_DERIVED_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    for id in selected {
        let module = required_module(catalog, id)?;
        for path in &module.generator_ownership.derived {
            if !MANAGER_DERIVED_PATHS.contains(&path.as_str()) {
                return Err(ManagerError::InvalidProject(format!(
                    "module `{id}` declares unsupported derived path `{path}`"
                )));
            }
            paths.insert(path.clone());
        }
    }
    Ok(paths)
}

pub(crate) fn render_managed_derived(
    path: &str,
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    snapshot: &ProjectSnapshot,
) -> Result<String, ManagerError> {
    if !MANAGER_DERIVED_PATHS.contains(&path) {
        return Err(ManagerError::InvalidProject(format!(
            "no deterministic renderer exists for derived file `{path}`"
        )));
    }
    render_derived_with_retained_volumes(
        path,
        catalog,
        selected,
        &snapshot.state.service,
        &snapshot.state.retained_compose_volumes,
    )
}

fn diagnose_snapshot(catalog: &ModuleCatalog, snapshot: &ProjectSnapshot) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Err(error) = catalog.validate() {
        diagnostics.push(diagnostic("catalog-invalid", None, error.to_string()));
        return diagnostics;
    }
    if let Err(error) = validate_application_template_catalog(catalog) {
        diagnostics.push(diagnostic("catalog-invalid", None, error));
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

    diagnostics.extend(snapshot.provenance_diagnostics.iter().cloned());
    let selected = selected_ids(&snapshot.state);
    let derived_paths = match selected_derived_paths(catalog, &selected) {
        Ok(paths) => paths,
        Err(error) => {
            diagnostics.push(diagnostic("catalog-invalid", None, error.to_string()));
            return diagnostics;
        }
    };
    diagnose_managed_region_inventory(snapshot, &derived_paths, &mut diagnostics);
    let current_identity = snapshot.state.framework == snapshot.release_identity;
    diagnose_state_selection(
        catalog,
        snapshot,
        &selected,
        current_identity,
        &mut diagnostics,
    );
    diagnose_owned_files(
        catalog,
        snapshot,
        &selected,
        current_identity,
        &mut diagnostics,
    );
    let recorded = diagnose_managed_records(
        catalog,
        snapshot,
        &selected,
        current_identity,
        &mut diagnostics,
    );
    diagnose_untracked_regions(snapshot, &recorded, &mut diagnostics);
    diagnostics.sort();
    diagnostics.dedup();
    diagnostics
}

fn diagnose_managed_region_inventory(
    snapshot: &ProjectSnapshot,
    derived_paths: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for &(path, id) in SCHEMA_2_MANAGED_REGIONS {
        if snapshot.state.managed_region(path, id).is_none() {
            diagnostics.push(diagnostic(
                "managed-region-state-missing",
                Some(PROJECT_STATE_PATH),
                format!("schema 2 state must record managed region `{id}` in `{path}`"),
            ));
        }
        if snapshot.state.ownership_of(path) != Some(OwnershipKind::ApplicationOwned) {
            diagnostics.push(diagnostic(
                "managed-path-ownership-invalid",
                Some(path),
                format!(
                    "schema 2 managed-region target `{path}` must be application-owned outside its region"
                ),
            ));
        }
    }
    for record in &snapshot.state.managed_regions {
        if !SCHEMA_2_MANAGED_REGIONS
            .iter()
            .any(|&(path, id)| record.path == path && record.id == id)
        {
            diagnostics.push(diagnostic(
                "managed-region-state-unsupported",
                Some(PROJECT_STATE_PATH),
                format!(
                    "schema 2 state contains unsupported managed region `{}` in `{}`",
                    record.id, record.path
                ),
            ));
        }
    }
    for path in derived_paths {
        let ownership_is_migratable = snapshot
            .files
            .get(path)
            .is_some_and(|current| is_migratable_legacy_react_index(snapshot, path, current));
        if snapshot.state.ownership_of(path) != Some(OwnershipKind::Derived)
            && !ownership_is_migratable
        {
            diagnostics.push(diagnostic(
                "derived-ownership-invalid",
                Some(path),
                format!("schema 2 derived file `{path}` must be recorded as derived"),
            ));
        }
    }
    for record in snapshot
        .state
        .ownership
        .iter()
        .filter(|record| record.kind == OwnershipKind::Derived)
    {
        if !derived_paths.contains(&record.path) {
            diagnostics.push(diagnostic(
                "derived-ownership-unexpected",
                Some(&record.path),
                format!(
                    "schema 2 state records inactive derived file `{}`",
                    record.path
                ),
            ));
        }
    }
}

fn diagnose_state_selection(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    current_identity: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for module in &snapshot.state.modules {
        if matches!(module.id.as_str(), "generator" | "test-support") {
            diagnostics.push(diagnostic(
                "tooling-module-forbidden",
                Some(PROJECT_STATE_PATH),
                format!(
                    "tooling module `{}` cannot be selected in schema 2 runtime state",
                    module.id
                ),
            ));
        }
    }
    if !current_identity {
        diagnostics.push(diagnostic(
            "release-mismatch",
            Some(PROJECT_STATE_PATH),
            format!(
                "project framework {} {} @ {} does not exactly match executing release {} {} @ {}; install the recorded CLI to inspect its generated bytes or run update",
                snapshot.state.framework.version(),
                snapshot.state.framework.repository(),
                snapshot.state.framework.revision(),
                snapshot.release_identity.version(),
                snapshot.release_identity.repository(),
                snapshot.release_identity.revision(),
            ),
        ));
        return;
    }
    if catalog.bundle_version != snapshot.release_identity.version()
        || snapshot.state.profile.version != catalog.bundle_version
    {
        diagnostics.push(diagnostic(
            "release-version-mismatch",
            Some(PROJECT_STATE_PATH),
            format!(
                "catalog/profile versions {}/{} do not match release {}",
                catalog.bundle_version,
                snapshot.state.profile.version,
                snapshot.release_identity.version()
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
    match catalog.validate_selection(selected) {
        Err(error) => diagnostics.push(diagnostic(
            "selection-invalid",
            Some(PROJECT_STATE_PATH),
            error.to_string(),
        )),
        Ok(()) => match catalog.composition_order(selected) {
            Ok(ordered)
                if ordered.iter().map(|module| module.id.as_str()).eq(snapshot
                    .state
                    .modules
                    .iter()
                    .map(|module| module.id.as_str())) => {}
            Ok(_) => diagnostics.push(diagnostic(
                "module-order-mismatch",
                Some(PROJECT_STATE_PATH),
                "selected modules are not recorded in canonical prerequisite order".to_owned(),
            )),
            Err(error) => diagnostics.push(diagnostic(
                "selection-invalid",
                Some(PROJECT_STATE_PATH),
                error.to_string(),
            )),
        },
    }
}

fn diagnose_owned_files(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    current_identity: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if snapshot.state.ownership_of("Cargo.lock") != Some(OwnershipKind::DependencyLock) {
        diagnostics.push(diagnostic(
            "dependency-lock-ownership-invalid",
            Some("Cargo.lock"),
            "schema-2 state must own Cargo.lock as dependency-lock".to_owned(),
        ));
    }
    for ownership in &snapshot.state.ownership {
        if (ownership.path == "Cargo.lock" && ownership.kind != OwnershipKind::DependencyLock)
            || (ownership.kind == OwnershipKind::DependencyLock && ownership.path != "Cargo.lock")
        {
            diagnostics.push(diagnostic(
                "dependency-lock-ownership-invalid",
                Some(&ownership.path),
                "Cargo.lock is the only dependency-lock path and must not use another ownership kind"
                    .to_owned(),
            ));
        }
        if ownership.kind == OwnershipKind::DependencyLock {
            if snapshot.lockfile.is_none() {
                diagnostics.push(diagnostic(
                    "owned-file-missing",
                    Some("Cargo.lock"),
                    "owned dependency lock `Cargo.lock` is missing".to_owned(),
                ));
            }
            continue;
        }
        let Some(contents) = snapshot.files.get(&ownership.path) else {
            diagnostics.push(diagnostic(
                "owned-file-missing",
                Some(&ownership.path),
                format!("owned file `{}` is missing", ownership.path),
            ));
            continue;
        };
        match ownership.kind {
            OwnershipKind::KitOwned => {
                diagnose_approved_hash(ownership, contents, diagnostics);
                if current_identity {
                    diagnose_kit_owned_file(snapshot, ownership, contents, diagnostics);
                }
            }
            OwnershipKind::Derived => {
                diagnose_approved_hash(ownership, contents, diagnostics);
                if current_identity {
                    diagnose_derived_file(
                        catalog,
                        snapshot,
                        selected,
                        ownership,
                        contents,
                        diagnostics,
                    );
                }
            }
            OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock => {}
        }
    }
}

fn diagnose_approved_hash(
    ownership: &OwnershipRecord,
    contents: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(approved) = ownership.approved_sha256.as_deref() else {
        return;
    };
    let actual = sha256_hex(contents.as_bytes());
    if actual != approved {
        diagnostics.push(diagnostic(
            "approved-hash-mismatch",
            Some(&ownership.path),
            format!(
                "{} file `{}` has SHA-256 {actual}, but state approves {approved}",
                match ownership.kind {
                    OwnershipKind::KitOwned => "kit-owned",
                    OwnershipKind::Derived => "derived",
                    OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock => {
                        "unhashed"
                    }
                },
                ownership.path
            ),
        ));
    }
}

fn diagnose_kit_owned_file(
    snapshot: &ProjectSnapshot,
    ownership: &OwnershipRecord,
    contents: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(approved) = snapshot.base_files.get(&ownership.path) else {
        diagnostics.push(diagnostic(
            "base-descriptor-missing",
            Some(&ownership.path),
            format!(
                "embedded base descriptor for kit-owned file `{}` is unavailable",
                ownership.path
            ),
        ));
        return;
    };
    match matches_approved_baseline(&ownership.path, contents, approved, &snapshot.state) {
        Ok(true) => {}
        Ok(false) => diagnostics.push(diagnostic(
            "kit-owned-drift",
            Some(&ownership.path),
            format!(
                "kit-owned file `{}` differs from its embedded base descriptor outside managed regions",
                ownership.path
            ),
        )),
        Err(error) => diagnostics.push(diagnostic(
            "kit-owned-drift",
            Some(&ownership.path),
            error.to_string(),
        )),
    }
}

fn diagnose_derived_file(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    ownership: &OwnershipRecord,
    contents: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match render_managed_derived(&ownership.path, catalog, selected, snapshot) {
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
    catalog: &ModuleCatalog,
    snapshot: &'a ProjectSnapshot,
    selected: &BTreeSet<String>,
    current_identity: bool,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeSet<(&'a str, &'a str)> {
    let mut recorded = BTreeSet::new();
    for record in &snapshot.state.managed_regions {
        recorded.insert((record.path.as_str(), record.id.as_str()));
        diagnose_managed_record(
            catalog,
            snapshot,
            selected,
            record,
            current_identity,
            diagnostics,
        );
    }
    recorded
}

fn diagnose_managed_record(
    catalog: &ModuleCatalog,
    snapshot: &ProjectSnapshot,
    selected: &BTreeSet<String>,
    record: &ManagedRegionRecord,
    current_identity: bool,
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
    if !current_identity {
        return;
    }
    match render_region(catalog, &record.id, selected, snapshot) {
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

fn diagnose_untracked_regions(
    snapshot: &ProjectSnapshot,
    recorded: &BTreeSet<(&str, &str)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (path, contents) in &snapshot.files {
        match parse_managed_regions(contents) {
            Ok(regions) => {
                for region in regions {
                    if recorded.contains(&(path.as_str(), region.id)) {
                        continue;
                    }
                    diagnostics.push(diagnostic(
                        "managed-region-untracked",
                        Some(path),
                        format!("managed region `{}` has no project state record", region.id),
                    ));
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

pub(crate) fn render_region(
    catalog: &ModuleCatalog,
    id: &str,
    selected: &BTreeSet<String>,
    snapshot: &ProjectSnapshot,
) -> Result<String, ManagerError> {
    match id {
        "framework-dependency" => {
            render_framework_dependency(catalog, selected, &snapshot.release_identity)
        }
        "modules" => render_modules_region(catalog, selected),
        _ => Err(ManagerError::InvalidProject(format!(
            "no deterministic renderer exists for managed region `{id}`"
        ))),
    }
}

fn render_framework_dependency(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    release_identity: &ReleaseIdentity,
) -> Result<String, ManagerError> {
    let ordered = catalog.composition_order(selected)?;
    if let Some(module) = ordered.iter().find(|module| module.kind == "tooling") {
        return Err(ManagerError::InvalidProject(format!(
            "tooling module `{}` cannot become a service-kit runtime feature",
            module.id
        )));
    }
    let mut content =
        String::from("[workspace.dependencies.service-kit]\npackage = \"omnius-service-kit\"\n");
    let _ = writeln!(content, "version = \"={}\"", release_identity.version());
    let _ = writeln!(content, "git = {:?}", release_identity.repository());
    let _ = writeln!(content, "rev = {:?}", release_identity.revision());
    content.push_str("default-features = false\nfeatures = [\n");
    for module in ordered {
        let _ = writeln!(content, "  {:?},", module.id);
    }
    content.push_str("]\n");
    Ok(content)
}

pub(crate) fn render_modules_region(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
) -> Result<String, ManagerError> {
    let mut content = String::new();
    for module in catalog.composition_order(selected)? {
        content.push_str("    \"");
        content.push_str(&module.id);
        content.push_str("\",\n");
    }
    Ok(content)
}

pub(crate) const REACT_INDEX_PATH: &str = "packages/web-sdk/src/react/index.ts";
pub(crate) const LEGACY_APPLICATION_REACT_INDEX: &str = concat!(
    "export * from \"./core.js\";\n",
    "export * from \"./auth.js\";\n",
    "export * from \"./capabilities.js\";\n",
);

const UNCONDITIONAL_DERIVED_PATHS: &[&str] = &[
    "config/reference.toml",
    "docs/module-catalog.md",
    "ops/compose.yaml",
    "ops/Dockerfile",
];

pub(crate) const MANAGER_DERIVED_PATHS: &[&str] = &[
    "config/reference.toml",
    "docs/module-catalog.md",
    "ops/compose.yaml",
    "ops/Dockerfile",
    REACT_INDEX_PATH,
];

pub(crate) fn render_derived_with_retained_volumes(
    path: &str,
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    service_name: &str,
    retained_volumes: &[String],
) -> Result<String, ManagerError> {
    match path {
        "docs/module-catalog.md" => render_selected_module_catalog(catalog, selected),
        "config/reference.toml" => render_reference_config(catalog, selected, service_name),
        "ops/compose.yaml" => render_compose(catalog, selected, service_name, retained_volumes),
        "ops/Dockerfile" => render_managed_dockerfile(service_name, selected)
            .map_err(|error| ManagerError::InvalidProject(error.to_string())),
        REACT_INDEX_PATH => Ok(render_react_index(selected)),
        _ => Err(ManagerError::InvalidProject(format!(
            "no deterministic derived renderer exists for `{path}`"
        ))),
    }
}
fn render_react_index(selected: &BTreeSet<String>) -> String {
    const EXPORTS: &[(&str, &str)] = &[
        ("web-react", "core"),
        ("web-auth", "auth"),
        ("web-realtime", "realtime"),
        ("web-forms", "forms"),
        ("web-local-state", "local-state"),
        ("web-react", "capabilities"),
        ("web-tenancy", "tenant"),
        ("web-uploads", "uploads"),
        ("web-llm", "llm"),
    ];

    let mut content = String::with_capacity(256);
    for &(module, export) in EXPORTS {
        if selected.contains(module) {
            content.push_str("export * from \"./");
            content.push_str(export);
            content.push_str(".js\";\n");
        }
    }
    content
}

fn render_selected_module_catalog(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
) -> Result<String, ManagerError> {
    let mut output = String::from(
        "# Selected service modules\n\n| Module | Version | Provider slot |\n|---|---:|---|\n",
    );
    for id in selected {
        let module = required_module(catalog, id)?;
        writeln!(
            output,
            "| `{}` | `{}` | {} |",
            module.id,
            module.version,
            module.provider_slot.as_deref().unwrap_or("-")
        )
        .map_err(|_| ManagerError::InvalidProject("cannot render module catalog".to_owned()))?;
    }
    output.push_str(
        "\n## Runtime dependencies\n\n| Dependency | Resolution | Required environment |\n|---|---|---|\n",
    );
    for dependency in catalog.selected_runtime_dependencies(selected)? {
        match dependency {
            RuntimeDependencyDescriptor::Compose { id, service, .. } => {
                writeln!(
                    output,
                    "| `{}` | Compose service `{service}` | development-only bindings managed in `ops/compose.yaml` |",
                    id.as_str()
                )
            }
            RuntimeDependencyDescriptor::External { id, bindings } => {
                let environment = bindings
                    .iter()
                    .map(|binding| format!("`{}`", binding.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(
                    output,
                    "| `{}` | External (no generated container) | {environment} |",
                    id.as_str()
                )
            }
        }
        .map_err(|_| ManagerError::InvalidProject("cannot render module catalog".to_owned()))?;
    }
    Ok(output)
}

fn render_compose(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    _service_name: &str,
    retained_volumes: &[String],
) -> Result<String, ManagerError> {
    let dependencies = catalog.selected_runtime_dependencies(selected)?;
    let migration_owner = dependencies.iter().find_map(|dependency| {
        let RuntimeDependencyDescriptor::Compose {
            service,
            migration: Some(migration),
            ..
        } = dependency
        else {
            return None;
        };
        selected
            .contains(&migration.required_module)
            .then_some((service.as_str(), migration))
    });
    let application_environment =
        compose_application_environment(&dependencies, migration_owner.is_some())?;

    let mut output = String::from("services:\n  app:\n");
    push_compose_application(
        &mut output,
        &dependencies,
        &application_environment,
        migration_owner.is_some(),
    )?;
    push_compose_migration(&mut output, migration_owner, &application_environment)?;
    push_compose_dependencies(&mut output, &dependencies, retained_volumes)?;
    Ok(output)
}

fn compose_application_environment<'a>(
    dependencies: &[&'a RuntimeDependencyDescriptor],
    has_migration_owner: bool,
) -> Result<BTreeMap<&'a str, String>, ManagerError> {
    let mut environment: BTreeMap<&'a str, String> =
        BTreeMap::from([("OMNIUS__SERVER__LISTEN_ADDRESS", "0.0.0.0:3000".to_owned())]);
    for dependency in dependencies {
        match dependency {
            RuntimeDependencyDescriptor::Compose {
                application_environment: bindings,
                ..
            } => {
                for binding in bindings {
                    if binding.name == "OMNIUS__MIGRATIONS__RUN_ON_STARTUP" && !has_migration_owner
                    {
                        continue;
                    }
                    insert_compose_environment(&mut environment, &binding.name, &binding.value)?;
                }
            }
            RuntimeDependencyDescriptor::External { bindings, .. } => {
                for binding in bindings {
                    insert_compose_environment(
                        &mut environment,
                        &binding.name,
                        &format!("${{{}:?{}}}", binding.name, binding.message),
                    )?;
                }
            }
        }
    }
    Ok(environment)
}

fn push_compose_application(
    output: &mut String,
    dependencies: &[&RuntimeDependencyDescriptor],
    application_environment: &BTreeMap<&str, String>,
    has_migration_owner: bool,
) -> Result<(), ManagerError> {
    push_generated_build(output, 4);
    output.push_str("    environment:\n");
    push_compose_environment(output, application_environment, 6)?;
    if dependencies
        .iter()
        .any(|dependency| matches!(dependency, RuntimeDependencyDescriptor::Compose { .. }))
    {
        output.push_str("    depends_on:\n");
        let mut compose_services = dependencies
            .iter()
            .filter_map(|dependency| {
                let RuntimeDependencyDescriptor::Compose { service, .. } = dependency else {
                    return None;
                };
                Some(service.as_str())
            })
            .collect::<Vec<_>>();
        compose_services.sort_unstable();
        for service in compose_services {
            writeln!(
                output,
                "      {service}:\n        condition: service_healthy"
            )
            .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        }
        if has_migration_owner {
            output.push_str("      migrate:\n        condition: service_completed_successfully\n");
        }
    }
    output.push_str(
        "    ports:\n    - \"127.0.0.1:3000:3000\"\n    read_only: true\n    tmpfs:\n    - /tmp:size=16m,mode=1777\n    security_opt:\n    - no-new-privileges:true\n",
    );
    Ok(())
}

fn push_compose_migration(
    output: &mut String,
    migration_owner: Option<(&str, &ComposeMigration)>,
    application_environment: &BTreeMap<&str, String>,
) -> Result<(), ManagerError> {
    let Some((service, migration)) = migration_owner else {
        return Ok(());
    };
    output.push_str("  migrate:\n");
    push_generated_build(output, 4);
    output.push_str("    command: [");
    for (index, argument) in migration.command.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        push_yaml_string(output, argument)?;
    }
    output.push_str("]\n    environment:\n");
    let migration_environment = application_environment
        .iter()
        .filter(|(name, _)| **name != "OMNIUS__SERVER__LISTEN_ADDRESS")
        .map(|(name, value)| (*name, value.clone()))
        .collect::<BTreeMap<_, _>>();
    push_compose_environment(output, &migration_environment, 6)?;
    writeln!(
        output,
        "    depends_on:\n      {service}:\n        condition: service_healthy"
    )
    .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
    output.push_str(
        "    restart: \"no\"\n    read_only: true\n    tmpfs:\n    - /tmp:size=16m,mode=1777\n    security_opt:\n    - no-new-privileges:true\n",
    );
    Ok(())
}

fn push_compose_dependencies(
    output: &mut String,
    dependencies: &[&RuntimeDependencyDescriptor],
    retained_volumes: &[String],
) -> Result<(), ManagerError> {
    let mut compose_dependencies = dependencies
        .iter()
        .filter_map(|dependency| {
            matches!(dependency, RuntimeDependencyDescriptor::Compose { .. }).then_some(*dependency)
        })
        .collect::<Vec<_>>();
    compose_dependencies.sort_by_key(|dependency| match dependency {
        RuntimeDependencyDescriptor::Compose { service, .. } => service.as_str(),
        RuntimeDependencyDescriptor::External { .. } => "",
    });
    let mut volumes = retained_volumes.iter().cloned().collect::<BTreeSet<_>>();
    for dependency in compose_dependencies {
        let RuntimeDependencyDescriptor::Compose {
            service,
            image,
            volume,
            volume_mount,
            healthcheck,
            service_environment,
            ..
        } = dependency
        else {
            continue;
        };
        volumes.insert(volume.clone());
        writeln!(output, "  {service}:\n    image: {image}")
            .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        output.push_str("    environment:\n");
        let environment = service_environment
            .iter()
            .map(|binding| (binding.name.as_str(), binding.value.clone()))
            .collect::<BTreeMap<_, _>>();
        push_compose_environment(output, &environment, 6)?;
        output.push_str("    volumes:\n    - ");
        push_yaml_string(output, &format!("{volume}:{volume_mount}"))?;
        output.push_str("\n    healthcheck:\n      test: [");
        for (index, argument) in healthcheck.test.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            push_yaml_string(output, argument)?;
        }
        writeln!(
            output,
            "]\n      interval: {}\n      timeout: {}\n      retries: {}",
            healthcheck.interval, healthcheck.timeout, healthcheck.retries
        )
        .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
    }
    if !volumes.is_empty() {
        output.push_str("volumes:\n");
        for volume in volumes {
            writeln!(output, "  {volume}:")
                .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        }
    }
    Ok(())
}

fn insert_compose_environment<'a>(
    environment: &mut BTreeMap<&'a str, String>,
    name: &'a str,
    value: &str,
) -> Result<(), ManagerError> {
    if let Some(existing) = environment.insert(name, value.to_owned())
        && existing != value
    {
        return Err(ManagerError::InvalidProject(format!(
            "runtime dependencies define conflicting Compose binding `{name}`"
        )));
    }
    Ok(())
}

fn push_generated_build(output: &mut String, indent: usize) {
    let padding = " ".repeat(indent);
    let _ = writeln!(
        output,
        "{padding}build:\n{padding}  context: ..\n{padding}  dockerfile: ops/Dockerfile"
    );
}

fn push_compose_environment(
    output: &mut String,
    environment: &BTreeMap<&str, String>,
    indent: usize,
) -> Result<(), ManagerError> {
    let padding = " ".repeat(indent);
    for (name, value) in environment {
        write!(output, "{padding}{name}: ")
            .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        push_yaml_string(output, value)?;
        output.push('\n');
    }
    Ok(())
}

fn push_yaml_string(output: &mut String, value: &str) -> Result<(), ManagerError> {
    let encoded = serde_json::to_string(value).map_err(|error| {
        ManagerError::InvalidProject(format!("cannot encode Compose scalar: {error}"))
    })?;
    output.push_str(&encoded);
    Ok(())
}

fn render_reference_config(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
    service_name: &str,
) -> Result<String, ManagerError> {
    catalog.validate_selection(selected)?;
    let mut document = toml::Table::new();
    for id in selected {
        let module = required_module(catalog, id)?;
        for field in &module.configuration.fields {
            let components = field.path.split('.').collect::<Vec<_>>();
            insert_reference_value(
                &mut document,
                &components,
                field.reference_default.as_ref(),
                service_name,
            )?;
        }
    }
    let rendered = toml::to_string(&document).map_err(|error| {
        ManagerError::InvalidProject(format!("cannot render reference configuration: {error}"))
    })?;
    Ok(format!(
        "# Generated safe runtime configuration. Secrets are supplied through the process environment.\n{rendered}"
    ))
}

fn insert_reference_value(
    table: &mut toml::Table,
    path: &[&str],
    value: Option<&ConfigurationValue>,
    service_name: &str,
) -> Result<(), ManagerError> {
    let Some((component, remaining)) = path.split_first() else {
        return Err(ManagerError::InvalidProject(
            "configuration field path is empty".to_owned(),
        ));
    };
    if remaining.is_empty() {
        if let Some(value) = value {
            table.insert(
                (*component).to_owned(),
                reference_toml_value(value, service_name),
            );
        }
        return Ok(());
    }
    let entry = table
        .entry((*component).to_owned())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let nested = entry.as_table_mut().ok_or_else(|| {
        ManagerError::InvalidProject(format!(
            "configuration field `{component}` conflicts with a table"
        ))
    })?;
    insert_reference_value(nested, remaining, value, service_name)
}

fn reference_toml_value(value: &ConfigurationValue, service_name: &str) -> toml::Value {
    match value {
        ConfigurationValue::String(value) => {
            toml::Value::String(value.replace("{{service-name}}", service_name))
        }
        ConfigurationValue::Integer(value) => toml::Value::Integer(*value),
        ConfigurationValue::Boolean(value) => toml::Value::Boolean(*value),
        ConfigurationValue::StringArray(values) => toml::Value::Array(
            values
                .iter()
                .map(|value| toml::Value::String(value.clone()))
                .collect(),
        ),
        ConfigurationValue::IntegerArray(values) => {
            toml::Value::Array(values.iter().copied().map(toml::Value::Integer).collect())
        }
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
            for id in removed {
                if let Some(index) = state
                    .profile
                    .additions
                    .iter()
                    .position(|addition| addition == id)
                {
                    state.profile.additions.remove(index);
                } else if !state.profile.removals.contains(id) {
                    state.profile.removals.push(id.clone());
                }
            }
        }
        PlanAction::ProfileSet => {
            requested.clone_into(&mut state.profile.id);
            state.profile.additions.clear();
            state.profile.removals.clear();
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

/// Returns whether a path names migrations, persisted data, or history that
/// module removal must retain.
#[must_use]
pub fn preserves_historical_path(path: &str) -> bool {
    let mut components = path.split('/');
    let first = components.next().unwrap_or_default();
    if matches!(first, "migration" | "migrations" | "data" | "history") {
        return true;
    }
    let historical_directory = components
        .clone()
        .any(|component| matches!(component, "data" | "history"));
    let nested_migration =
        components.any(|component| matches!(component, "migration" | "migrations"));
    historical_directory
        || (nested_migration
            && Path::new(path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("sql")))
}

fn diagnostic(code: &str, path: Option<&str>, message: String) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        path: path.map(str::to_owned),
        message,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CargoGraph, CargoResolverMode, CargoResolverResult, KIT_VERSION,
        cargo_resolver::CargoResolverError,
        release::CANONICAL_REPOSITORY,
        upgrade::{TEST_LEGACY_VERSION, test_legacy_files},
    };
    use omnius_test_support::CleanDirectory;

    struct LegacyCutoverResolver;

    impl LockfileResolver for LegacyCutoverResolver {
        fn resolve(
            &self,
            request: &CargoResolverRequest,
        ) -> Result<CargoResolverResult, CargoResolverError> {
            if request.mode() != &CargoResolverMode::LegacyCutover {
                return Err(CargoResolverError::InvalidRequest(
                    "schema-1 update did not request legacy cutover resolution".to_owned(),
                ));
            }
            for forbidden in [".sqlx", "specs", "templates", "xtask", "crates"] {
                if request.candidate_project().join(forbidden).exists() {
                    return Err(CargoResolverError::InvalidRequest(format!(
                        "staged legacy cutover retained `{forbidden}`"
                    )));
                }
            }
            Ok(CargoResolverResult::from_parts(
                b"version = 4\n\n# sealed legacy cutover lock\n".to_vec(),
                Some(CargoGraph::default()),
                CargoGraph::default(),
                None,
            ))
        }
    }

    fn materialize_legacy_project(root: &Path) -> Result<(), Box<dyn Error>> {
        for (relative, contents) in test_legacy_files() {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, contents)?;
        }
        Ok(())
    }

    fn test_release_identity() -> Result<ReleaseIdentity, Box<dyn Error>> {
        Ok(ReleaseIdentity::new(
            KIT_VERSION,
            CANONICAL_REPOSITORY,
            "0000000000000000000000000000000000000001",
        )?)
    }

    #[test]
    fn schema_one_fixture_updates_only_through_a_sealed_cutover() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("minimal-schema-one-cutover")?;
        materialize_legacy_project(directory.path())?;
        let application_path = directory.path().join("apps/service/src/application.rs");
        let migration_path = directory
            .path()
            .join("migrations/9000000000000000000_fixture.sql");
        let application_before = fs::read(&application_path)?;
        let migration_before = fs::read(&migration_path)?;
        let legacy_lock = fs::read(directory.path().join("Cargo.lock"))?;
        let catalog = ModuleCatalog::bundled()?;
        let identity = test_release_identity()?;
        let manager = ProjectManager::new(directory.path(), &identity, &catalog);

        let sealed = manager.seal_update_with(false, &LegacyCutoverResolver)?;
        assert_eq!(sealed.plan().action, PlanAction::Upgrade);
        assert!(sealed.resolution().is_some());
        let lock_index = sealed
            .plan()
            .operations
            .iter()
            .position(|operation| matches!(operation, PlanOperation::WriteResolvedLock { .. }))
            .ok_or("sealed cutover omitted resolved lock bytes")?;
        assert!(lock_index + 1 < sealed.plan().operations.len());
        assert!(matches!(
            sealed.plan().operations.last(),
            Some(PlanOperation::WriteState { .. })
        ));
        manager.apply(&sealed)?;

        assert_ne!(fs::read(directory.path().join("Cargo.lock"))?, legacy_lock);
        assert_eq!(fs::read(&application_path)?, application_before);
        assert_eq!(fs::read(&migration_path)?, migration_before);
        for forbidden in [".sqlx", "specs", "templates", "xtask", "crates"] {
            assert!(!directory.path().join(forbidden).exists(), "{forbidden}");
        }
        let state = ProjectState::parse(&fs::read_to_string(
            directory.path().join(PROJECT_STATE_PATH),
        )?)?;
        assert_eq!(state.framework, identity);
        assert_ne!(state.framework.version(), TEST_LEGACY_VERSION);

        let repeated = manager.seal_update_with(false, &LegacyCutoverResolver)?;
        assert!(repeated.is_empty());
        assert!(repeated.resolution().is_none());
        assert!(manager.doctor()?.healthy);
        Ok(())
    }

    #[test]
    fn schema_one_rejects_unknown_empty_forbidden_roots() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("schema-one-empty-forbidden-root")?;
        materialize_legacy_project(directory.path())?;
        fs::create_dir_all(directory.path().join("xtask"))?;
        let catalog = ModuleCatalog::bundled()?;
        let identity = test_release_identity()?;
        let manager = ProjectManager::new(directory.path(), &identity, &catalog);

        let error = manager
            .seal_update_with(false, &LegacyCutoverResolver)
            .err()
            .ok_or("unknown empty legacy directory must be rejected")?;

        assert!(error.to_string().contains("unknown directory `xtask`"));
        assert_eq!(
            toml::from_str::<toml::Value>(&fs::read_to_string(
                directory.path().join(PROJECT_STATE_PATH),
            )?)?["schema_version"]
                .as_integer(),
            Some(1),
        );
        Ok(())
    }

    #[test]
    fn react_barrel_exports_only_selected_adapters() -> Result<(), Box<dyn Error>> {
        let catalog = ModuleCatalog::bundled()?;
        let mut selected = ["web-auth", "web-llm", "web-react", "web-tenancy"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();

        assert!(
            selected_derived_paths(&catalog, &selected)?
                .contains("packages/web-sdk/src/react/index.ts")
        );
        assert_eq!(
            render_react_index(&selected),
            concat!(
                "export * from \"./core.js\";\n",
                "export * from \"./auth.js\";\n",
                "export * from \"./capabilities.js\";\n",
                "export * from \"./tenant.js\";\n",
                "export * from \"./llm.js\";\n",
            )
        );

        selected.remove("web-tenancy");
        assert!(!render_react_index(&selected).contains("./tenant.js"));
        selected.remove("web-llm");
        assert!(!render_react_index(&selected).contains("./llm.js"));
        Ok(())
    }

    #[test]
    fn thin_candidate_rejects_untracked_omnius_crate_without_manifest() -> Result<(), Box<dyn Error>>
    {
        let directory = CleanDirectory::new("thin-unknown-omnius-crate")?;
        let source = directory.path().join("crates/omnius-extra/src/lib.rs");
        fs::create_dir_all(source.parent().ok_or("source path has no parent")?)?;
        fs::write(source, "pub const EXTRA: bool = true;\n")?;

        let Err(error) = ensure_thin_candidate_tree(directory.path()) else {
            return Err("untracked Omnius crate must be rejected".into());
        };
        assert!(error.to_string().contains("omnius-extra"));
        Ok(())
    }
}
