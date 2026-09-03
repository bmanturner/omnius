use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use serde::Deserialize;

use crate::release::ReleaseIdentity;

const CARGO: &str = "cargo";
const FRAMEWORK_PACKAGE: &str = "omnius-service-kit";
const ROOT_FRAMEWORK_ALIAS: &str = "service-kit";
const LOCKFILE_READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// The Cargo operation used to resolve a candidate lifecycle plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CargoResolverMode {
    /// Resolve a project that does not yet have a lockfile.
    New,
    /// Conservatively update the framework package in an existing lockfile.
    UpdateLocked,
    /// Reconcile a schema-1 local framework closure into the canonical Git package layout.
    LegacyCutover,
    /// Update the framework package to one exact Git commit.
    RevisionPrecise {
        /// Full lowercase commit revision passed to Cargo's `--precise` option.
        revision: String,
    },
}

/// Inputs for one Cargo-authoritative lockfile resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoResolverRequest {
    /// Original project used for the before graph, absent only for `new`.
    current_project: Option<PathBuf>,
    /// Staged candidate project Cargo may modify.
    candidate_project: PathBuf,
    /// Lockfile update operation.
    mode: CargoResolverMode,
    /// Release identity expected in the before graph, absent only for `new`.
    before_release: Option<ReleaseIdentity>,
    /// Release identity required in the candidate graph.
    target_release: ReleaseIdentity,
    /// Whether every Cargo command receives `--offline`.
    offline: bool,
}

impl CargoResolverRequest {
    /// Constructs a request for a new project with no existing lockfile.
    #[must_use]
    pub fn new_project(
        candidate_project: impl Into<PathBuf>,
        target_release: ReleaseIdentity,
        offline: bool,
    ) -> Self {
        Self {
            current_project: None,
            candidate_project: candidate_project.into(),
            mode: CargoResolverMode::New,
            before_release: None,
            target_release,
            offline,
        }
    }

    /// Constructs a request for a schema-2 feature or profile change.
    #[must_use]
    pub fn update_locked(
        current_project: impl Into<PathBuf>,
        candidate_project: impl Into<PathBuf>,
        release: ReleaseIdentity,
        offline: bool,
    ) -> Self {
        Self {
            current_project: Some(current_project.into()),
            candidate_project: candidate_project.into(),
            mode: CargoResolverMode::UpdateLocked,
            before_release: Some(release.clone()),
            target_release: release,
            offline,
        }
    }
    /// Constructs a request that cuts a schema-1 local framework closure over to schema 2.
    #[must_use]
    pub fn legacy_cutover(
        current_project: impl Into<PathBuf>,
        candidate_project: impl Into<PathBuf>,
        target_release: ReleaseIdentity,
        offline: bool,
    ) -> Self {
        Self {
            current_project: Some(current_project.into()),
            candidate_project: candidate_project.into(),
            mode: CargoResolverMode::LegacyCutover,
            before_release: None,
            target_release,
            offline,
        }
    }

    /// Constructs a request that moves an existing project to an exact revision.
    #[must_use]
    pub fn revision_precise(
        current_project: impl Into<PathBuf>,
        candidate_project: impl Into<PathBuf>,
        before_release: ReleaseIdentity,
        target_release: ReleaseIdentity,
        offline: bool,
    ) -> Self {
        Self {
            current_project: Some(current_project.into()),
            candidate_project: candidate_project.into(),
            mode: CargoResolverMode::RevisionPrecise {
                revision: target_release.revision().to_owned(),
            },
            before_release: Some(before_release),
            target_release,
            offline,
        }
    }

    /// Returns the staged current project, absent only for a new project.
    #[must_use]
    pub fn current_project(&self) -> Option<&Path> {
        self.current_project.as_deref()
    }

    /// Returns the staged candidate project Cargo is allowed to modify.
    #[must_use]
    pub fn candidate_project(&self) -> &Path {
        &self.candidate_project
    }

    /// Returns the requested Cargo resolution operation.
    #[must_use]
    pub const fn mode(&self) -> &CargoResolverMode {
        &self.mode
    }

    /// Returns the release expected in the current graph, absent only for a new project.
    #[must_use]
    pub const fn before_release(&self) -> Option<&ReleaseIdentity> {
        self.before_release.as_ref()
    }

    /// Returns the release required in the candidate graph.
    #[must_use]
    pub const fn target_release(&self) -> &ReleaseIdentity {
        &self.target_release
    }

    /// Returns whether every Cargo command must run offline.
    #[must_use]
    pub const fn offline(&self) -> bool {
        self.offline
    }
}

/// Exact lock bytes and validated Cargo graphs produced while sealing a plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoResolverResult {
    /// Exact bytes read from the candidate `Cargo.lock`.
    lockfile: Vec<u8>,
    /// Validated graph before the lifecycle change, absent only for `new`.
    before: Option<CargoGraph>,
    /// Validated graph after Cargo's locked no-rewrite verification.
    after: CargoGraph,
    /// Deterministic bounded framework difference, absent only for `new`.
    difference: Option<CargoGraphDifference>,
}

impl CargoResolverResult {
    /// Constructs a resolver result from exact lock bytes and validated graph projections.
    #[must_use]
    pub fn from_parts(
        lockfile: Vec<u8>,
        before: Option<CargoGraph>,
        after: CargoGraph,
        difference: Option<CargoGraphDifference>,
    ) -> Self {
        Self {
            lockfile,
            before,
            after,
            difference,
        }
    }

    /// Returns the exact resolved lockfile bytes.
    #[must_use]
    pub fn lockfile(&self) -> &[u8] {
        &self.lockfile
    }

    /// Returns the validated current graph, absent only for a new project.
    #[must_use]
    pub const fn before(&self) -> Option<&CargoGraph> {
        self.before.as_ref()
    }

    /// Returns the validated candidate graph.
    #[must_use]
    pub const fn after(&self) -> &CargoGraph {
        &self.after
    }

    /// Returns the validated bounded graph difference, absent only for a new project.
    #[must_use]
    pub const fn difference(&self) -> Option<&CargoGraphDifference> {
        self.difference.as_ref()
    }
}

/// One Cargo package identity from metadata format version 1.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CargoPackage {
    /// Stable graph identifier; project-local Cargo IDs are normalized to manifest-relative IDs.
    pub(crate) id: String,
    /// Cargo package name.
    pub(crate) name: String,
    /// Package version as reported by Cargo.
    pub(crate) version: String,
    /// Cargo source identifier, or `None` for a local workspace package.
    pub(crate) source: Option<String>,
}

impl CargoPackage {
    /// Returns Cargo's stable package identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns Cargo's source identifier for non-workspace packages.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

/// One dependency kind attached to a resolved edge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CargoDependencyKind {
    /// Cargo dependency kind. `None` is the normal dependency kind.
    pub(crate) kind: Option<String>,
    /// Optional target-platform expression.
    pub(crate) target: Option<String>,
}

impl CargoDependencyKind {
    /// Returns the Cargo dependency kind; `None` is the normal kind.
    #[must_use]
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Returns the optional target-platform expression.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }
}

/// One named edge in Cargo's resolved package graph.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CargoDependency {
    /// Dependency alias exposed to the depending package.
    pub(crate) name: String,
    /// Stable target package identifier.
    pub(crate) package: String,
    /// Normal, development, or build contexts represented by this edge.
    pub(crate) kinds: BTreeSet<CargoDependencyKind>,
}

impl CargoDependency {
    /// Returns the dependency alias.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the target package identifier.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Returns all resolved dependency contexts for this edge.
    #[must_use]
    pub const fn kinds(&self) -> &BTreeSet<CargoDependencyKind> {
        &self.kinds
    }
}

/// One node in Cargo's resolved package graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoNode {
    /// Stable package identifier.
    pub(crate) id: String,
    /// Named resolved dependency edges.
    pub(crate) dependencies: BTreeSet<CargoDependency>,
    /// Features enabled for this package in the resolved graph.
    pub(crate) features: BTreeSet<String>,
}

impl CargoNode {
    /// Returns the stable package identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the node's resolved dependency edges.
    #[must_use]
    pub const fn dependencies(&self) -> &BTreeSet<CargoDependency> {
        &self.dependencies
    }

    /// Returns the features enabled for this package.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<String> {
        &self.features
    }
}

/// Deterministic, validated projection of Cargo metadata format version 1.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CargoGraph {
    /// Packages keyed by stable package identifier.
    packages: BTreeMap<String, CargoPackage>,
    /// Resolve nodes keyed by stable package identifier.
    nodes: BTreeMap<String, CargoNode>,
    /// Workspace package identifiers.
    workspace_members: BTreeSet<String>,
}

/// One fully-qualified graph edge used in deterministic graph differences.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CargoGraphEdge {
    /// Depending package identifier.
    pub(crate) from: String,
    /// Dependency alias.
    pub(crate) name: String,
    /// Target package identifier.
    pub(crate) to: String,
    /// Dependency kinds represented by the edge.
    pub(crate) kinds: BTreeSet<CargoDependencyKind>,
}

impl CargoGraphEdge {
    /// Returns the depending package identifier.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    /// Returns the dependency alias.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the target package identifier.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// Returns all dependency contexts represented by the edge.
    #[must_use]
    pub const fn kinds(&self) -> &BTreeSet<CargoDependencyKind> {
        &self.kinds
    }
}

/// A deterministic graph difference whose mutable scope was validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoGraphDifference {
    /// Old dependency closure rooted at `omnius-service-kit`.
    before_framework_closure: BTreeSet<String>,
    /// New dependency closure rooted at `omnius-service-kit`.
    after_framework_closure: BTreeSet<String>,
    /// Package identities added by the candidate resolution.
    added_packages: BTreeSet<String>,
    /// Package identities removed by the candidate resolution.
    removed_packages: BTreeSet<String>,
    /// Resolved edges added by the candidate resolution.
    added_edges: BTreeSet<CargoGraphEdge>,
    /// Resolved edges removed by the candidate resolution.
    removed_edges: BTreeSet<CargoGraphEdge>,
}

impl CargoGraphDifference {
    /// Returns the current framework dependency closure.
    #[must_use]
    pub const fn before_framework_closure(&self) -> &BTreeSet<String> {
        &self.before_framework_closure
    }

    /// Returns the candidate framework dependency closure.
    #[must_use]
    pub const fn after_framework_closure(&self) -> &BTreeSet<String> {
        &self.after_framework_closure
    }

    /// Returns package identities added by the candidate.
    #[must_use]
    pub const fn added_packages(&self) -> &BTreeSet<String> {
        &self.added_packages
    }

    /// Returns package identities removed by the candidate.
    #[must_use]
    pub const fn removed_packages(&self) -> &BTreeSet<String> {
        &self.removed_packages
    }

    /// Returns resolved edges added by the candidate.
    #[must_use]
    pub const fn added_edges(&self) -> &BTreeSet<CargoGraphEdge> {
        &self.added_edges
    }

    /// Returns resolved edges removed by the candidate.
    #[must_use]
    pub const fn removed_edges(&self) -> &BTreeSet<CargoGraphEdge> {
        &self.removed_edges
    }
}

/// Resolver seam used to seal exact Cargo lock bytes and package graphs.
pub trait LockfileResolver {
    /// Resolves and validates one candidate lifecycle request.
    ///
    /// # Errors
    ///
    /// Returns [`CargoResolverError`] when Cargo cannot resolve the candidate or when its
    /// lockfile and metadata violate the request.
    fn resolve(
        &self,
        request: &CargoResolverRequest,
    ) -> Result<CargoResolverResult, CargoResolverError>;
}

/// Production resolver that invokes the inherited Cargo executable.
#[derive(Clone, Copy, Debug, Default)]
pub struct CargoLockfileResolver;

impl LockfileResolver for CargoLockfileResolver {
    fn resolve(
        &self,
        request: &CargoResolverRequest,
    ) -> Result<CargoResolverResult, CargoResolverError> {
        resolve_lockfile(request)
    }
}

/// Runs Cargo exactly once for each required resolution step and seals its result.
///
/// # Errors
///
/// Returns [`CargoResolverError`] for invalid requests, failed Cargo commands, unsafe lockfiles,
/// invalid metadata, provenance mismatches, or out-of-scope graph changes.
pub fn resolve_lockfile(
    request: &CargoResolverRequest,
) -> Result<CargoResolverResult, CargoResolverError> {
    validate_request(request)?;

    validate_lockfile_inputs(request)?;
    let (before, before_framework) = match &request.mode {
        CargoResolverMode::New => (None, None),
        CargoResolverMode::LegacyCutover => {
            let project = request.current_project.as_deref().ok_or_else(|| {
                CargoResolverError::InvalidRequest(
                    "legacy cutover requires a current project".to_owned(),
                )
            })?;
            let graph = locked_metadata(project, request.offline)?;
            let framework = graph
                .validate_legacy_framework()
                .map_err(CargoResolverError::Graph)?;
            (Some(graph), Some(framework))
        }
        CargoResolverMode::UpdateLocked | CargoResolverMode::RevisionPrecise { .. } => {
            let project = request.current_project.as_deref().ok_or_else(|| {
                CargoResolverError::InvalidRequest(
                    "existing-project resolution requires a current project".to_owned(),
                )
            })?;
            let release = request.before_release.as_ref().ok_or_else(|| {
                CargoResolverError::InvalidRequest(
                    "existing schema-2 resolution requires a before-release identity".to_owned(),
                )
            })?;
            let graph = locked_metadata(project, request.offline)?;
            let framework = graph
                .validate_framework(release)
                .map_err(CargoResolverError::Graph)?;
            (Some(graph), Some(framework))
        }
    };

    match &request.mode {
        CargoResolverMode::New => {
            run_cargo(
                &request.candidate_project,
                cargo_args(&["generate-lockfile"], request.offline),
            )?;
        }
        CargoResolverMode::LegacyCutover => {
            unlocked_metadata(&request.candidate_project, request.offline)?;
        }
        CargoResolverMode::UpdateLocked => {
            run_cargo(
                &request.candidate_project,
                cargo_update_args(request.target_release.version(), None, request.offline),
            )?;
        }
        CargoResolverMode::RevisionPrecise { revision } => {
            let before_release = request.before_release.as_ref().ok_or_else(|| {
                CargoResolverError::InvalidRequest(
                    "revision update requires a before-release identity".to_owned(),
                )
            })?;
            run_cargo(
                &request.candidate_project,
                cargo_update_args(before_release.version(), Some(revision), request.offline),
            )?;
        }
    }

    let after = locked_metadata(&request.candidate_project, request.offline)?;
    let after_framework = after
        .validate_framework(&request.target_release)
        .map_err(CargoResolverError::Graph)?;

    let difference = match (before.as_ref(), before_framework.as_deref()) {
        (Some(graph), Some(before_framework))
            if matches!(request.mode, CargoResolverMode::LegacyCutover) =>
        {
            Some(
                graph
                    .bounded_difference_from_roots(&after, before_framework, &after_framework, true)
                    .map_err(CargoResolverError::Graph)?,
            )
        }
        (Some(graph), Some(_)) => Some(
            graph
                .bounded_framework_difference(&after)
                .map_err(CargoResolverError::Graph)?,
        ),
        (None, None) => None,
        _ => {
            return Err(CargoResolverError::InvalidRequest(
                "resolver graph roots are internally inconsistent".to_owned(),
            ));
        }
    };
    let lockfile = read_regular_lockfile(&request.candidate_project)?;

    Ok(CargoResolverResult {
        lockfile,
        before,
        after,
        difference,
    })
}

impl CargoGraph {
    /// Returns packages keyed by stable Cargo package identifier.
    #[must_use]
    pub const fn packages(&self) -> &BTreeMap<String, CargoPackage> {
        &self.packages
    }

    /// Returns resolve nodes keyed by stable Cargo package identifier.
    #[must_use]
    pub const fn nodes(&self) -> &BTreeMap<String, CargoNode> {
        &self.nodes
    }

    /// Returns the workspace package identifiers.
    #[must_use]
    pub const fn workspace_members(&self) -> &BTreeSet<String> {
        &self.workspace_members
    }

    /// Parses and structurally validates one `cargo metadata --format-version 1` document.
    ///
    /// # Errors
    ///
    /// Returns [`CargoMetadataError`] when the document is invalid JSON or contains an
    /// inconsistent package graph.
    pub fn from_metadata_json(bytes: &[u8]) -> Result<Self, CargoMetadataError> {
        let metadata: RawMetadata =
            serde_json::from_slice(bytes).map_err(CargoMetadataError::Json)?;
        Self::from_raw(metadata).map_err(CargoMetadataError::Graph)
    }

    /// Validates the canonical kit, workspace aliases, and every reachable Omnius package.
    ///
    /// # Errors
    ///
    /// Returns [`CargoGraphError`] unless the graph contains exactly one canonical framework
    /// package, at least one workspace edge using the canonical alias, and exact identities for
    /// reachable Omnius packages.
    pub fn validate_framework(&self, release: &ReleaseIdentity) -> Result<String, CargoGraphError> {
        let framework_ids = self
            .packages
            .values()
            .filter(|package| package.name == FRAMEWORK_PACKAGE)
            .map(|package| package.id.clone())
            .collect::<Vec<_>>();
        if framework_ids.len() != 1 {
            return Err(CargoGraphError::FrameworkPackageCount {
                actual: framework_ids,
            });
        }
        let framework_id = &framework_ids[0];

        let root_edges = self
            .workspace_members
            .iter()
            .filter_map(|member| self.nodes.get(member))
            .flat_map(|node| {
                node.dependencies
                    .iter()
                    .filter(move |dependency| dependency.package.as_str() == framework_id.as_str())
                    .map(move |dependency| (node.id.as_str(), dependency))
            })
            .collect::<Vec<_>>();
        if root_edges.is_empty() {
            return Err(CargoGraphError::RootFrameworkEdgeCount {
                framework: framework_id.clone(),
                actual: Vec::new(),
            });
        }
        for (root_id, root_edge) in &root_edges {
            if !cargo_names_equal(&root_edge.name, ROOT_FRAMEWORK_ALIAS) {
                return Err(CargoGraphError::RootAliasMismatch {
                    root: (*root_id).to_owned(),
                    expected: ROOT_FRAMEWORK_ALIAS,
                    actual: root_edge.name.clone(),
                });
            }
        }

        let expected_source = canonical_git_source(release);
        for package_id in self.dependency_closure(framework_id)? {
            let package = self.packages.get(&package_id).ok_or_else(|| {
                CargoGraphError::NodePackageMissing {
                    package: package_id.clone(),
                }
            })?;
            if package.name.starts_with("omnius-") {
                if package.version != release.version() {
                    return Err(CargoGraphError::OmniusVersionMismatch {
                        package: package.id.clone(),
                        expected: release.version().to_owned(),
                        actual: package.version.clone(),
                    });
                }
                if package.source.as_deref() != Some(expected_source.as_str()) {
                    return Err(CargoGraphError::OmniusSourceMismatch {
                        package: package.id.clone(),
                        expected: expected_source.clone(),
                        actual: package.source.clone(),
                    });
                }
            }
        }

        Ok(framework_id.clone())
    }
    fn validate_legacy_framework(&self) -> Result<String, CargoGraphError> {
        let framework_ids = self
            .packages
            .values()
            .filter(|package| {
                package.source.is_none()
                    && package
                        .id
                        .contains("workspace+crates/service-kit/Cargo.toml#")
            })
            .map(|package| package.id.clone())
            .collect::<Vec<_>>();
        let [framework_id] = framework_ids.as_slice() else {
            return Err(CargoGraphError::FrameworkPackageCount {
                actual: framework_ids,
            });
        };
        let closure = self.dependency_closure(framework_id)?;
        let root_edges = self
            .workspace_members
            .iter()
            .filter_map(|member| self.nodes.get(member))
            .flat_map(|node| {
                node.dependencies
                    .iter()
                    .filter(move |dependency| dependency.package == *framework_id)
                    .map(move |dependency| (node.id.as_str(), dependency))
            })
            .collect::<Vec<_>>();
        if root_edges.is_empty() {
            return Err(CargoGraphError::RootFrameworkEdgeCount {
                framework: framework_id.clone(),
                actual: Vec::new(),
            });
        }
        for (root, edge) in root_edges {
            if !cargo_names_equal(&edge.name, ROOT_FRAMEWORK_ALIAS) {
                return Err(CargoGraphError::RootAliasMismatch {
                    root: root.to_owned(),
                    expected: ROOT_FRAMEWORK_ALIAS,
                    actual: edge.name.clone(),
                });
            }
        }
        for package in self
            .packages
            .values()
            .filter(|package| package.name.starts_with("omnius-"))
        {
            if package.source.is_some() || !closure.contains(&package.id) {
                return Err(CargoGraphError::OmniusSourceMismatch {
                    package: package.id.clone(),
                    expected: "the verified legacy local framework closure".to_owned(),
                    actual: package.source.clone(),
                });
            }
        }
        Ok(framework_id.clone())
    }

    /// Compares two validated graphs and rejects changes outside their framework closures.
    ///
    /// # Errors
    ///
    /// Returns [`CargoGraphError`] when any package, feature, dependency edge, or workspace
    /// member outside the old/new framework dependency closures changes.
    pub fn bounded_framework_difference(
        &self,
        after: &Self,
    ) -> Result<CargoGraphDifference, CargoGraphError> {
        let before_framework = self.unique_framework_id()?;
        let after_framework = after.unique_framework_id()?;
        self.bounded_difference_from_roots(after, &before_framework, &after_framework, false)
    }

    fn bounded_difference_from_roots(
        &self,
        after: &Self,
        before_framework: &str,
        after_framework: &str,
        allow_framework_workspace_removal: bool,
    ) -> Result<CargoGraphDifference, CargoGraphError> {
        let before_closure = self.dependency_closure(before_framework)?;
        let after_closure = after.dependency_closure(after_framework)?;
        let mutable_ids = before_closure
            .union(&after_closure)
            .cloned()
            .collect::<BTreeSet<_>>();
        let ignored_before_boundary_ids = allow_framework_workspace_removal.then(|| {
            before_closure
                .iter()
                .filter(|package_id| {
                    package_id.as_str() == before_framework
                        || self
                            .packages
                            .get(package_id.as_str())
                            .is_some_and(|package| package.name.starts_with("omnius-"))
                })
                .cloned()
                .collect::<BTreeSet<_>>()
        });
        let ignored_after_boundary_ids =
            allow_framework_workspace_removal.then(|| BTreeSet::from([after_framework.to_owned()]));
        let legacy_boundary = ignored_before_boundary_ids
            .as_ref()
            .zip(ignored_after_boundary_ids.as_ref())
            .map(|(before_ignored, after_ignored)| LegacyBoundary {
                before_ignored,
                after_ignored,
                after_framework,
            });

        let workspace_unchanged = if allow_framework_workspace_removal {
            self.workspace_members
                .difference(&before_closure)
                .eq(after.workspace_members.difference(&after_closure))
        } else {
            self.workspace_members == after.workspace_members
        };
        if !workspace_unchanged {
            return Err(CargoGraphError::OutOfScopeWorkspaceChange {
                before: self.workspace_members.clone(),
                after: after.workspace_members.clone(),
            });
        }

        for package_id in self
            .packages
            .keys()
            .chain(after.packages.keys())
            .filter(|package_id| !mutable_ids.contains(*package_id))
        {
            if self.packages.get(package_id) != after.packages.get(package_id) {
                return Err(CargoGraphError::OutOfScopePackageChange {
                    package: package_id.clone(),
                });
            }

            let before_node = self.nodes.get(package_id);
            let after_node = after.nodes.get(package_id);
            if !nodes_equal_outside_mutable_closures(
                self,
                before_node,
                after,
                after_node,
                &mutable_ids,
                legacy_boundary,
            )? {
                return Err(CargoGraphError::OutOfScopeNodeChange {
                    package: package_id.clone(),
                });
            }
        }

        let before_packages = self.packages.keys().cloned().collect::<BTreeSet<_>>();
        let after_packages = after.packages.keys().cloned().collect::<BTreeSet<_>>();
        let before_edges = self.edges();
        let after_edges = after.edges();

        Ok(CargoGraphDifference {
            before_framework_closure: before_closure,
            after_framework_closure: after_closure,
            added_packages: after_packages
                .difference(&before_packages)
                .cloned()
                .collect(),
            removed_packages: before_packages
                .difference(&after_packages)
                .cloned()
                .collect(),
            added_edges: after_edges.difference(&before_edges).cloned().collect(),
            removed_edges: before_edges.difference(&after_edges).cloned().collect(),
        })
    }

    fn from_raw(metadata: RawMetadata) -> Result<Self, CargoGraphError> {
        let RawMetadata {
            packages: raw_packages,
            resolve,
            workspace_members,
            workspace_root,
        } = metadata;
        let workspace_root = workspace_root.as_deref().map(Path::new);
        let mut id_map = BTreeMap::new();
        let mut packages = BTreeMap::new();
        for package in raw_packages {
            let raw_id = package.id.clone();
            let package_id = normalized_package_id(&package, workspace_root);
            if id_map.insert(raw_id.clone(), package_id.clone()).is_some() {
                return Err(CargoGraphError::DuplicatePackageId { package: raw_id });
            }
            let package = CargoPackage {
                id: package_id.clone(),
                name: package.name,
                version: package.version,
                source: package.source,
            };
            if packages.insert(package_id.clone(), package).is_some() {
                return Err(CargoGraphError::DuplicatePackageId {
                    package: package_id,
                });
            }
        }

        let resolve = resolve.ok_or(CargoGraphError::MissingResolve)?;
        let mut nodes = BTreeMap::new();
        for node in resolve.nodes {
            let dependencies = node
                .deps
                .into_iter()
                .map(|dependency| CargoDependency {
                    name: dependency.name,
                    package: translated_package_id(&id_map, &dependency.pkg),
                    kinds: dependency
                        .dep_kinds
                        .into_iter()
                        .map(|kind| CargoDependencyKind {
                            kind: kind.kind,
                            target: kind.target,
                        })
                        .collect(),
                })
                .collect();
            let package_id = translated_package_id(&id_map, &node.id);
            let node = CargoNode {
                id: package_id.clone(),
                dependencies,
                features: node.features.into_iter().collect(),
            };
            if nodes.insert(package_id.clone(), node).is_some() {
                return Err(CargoGraphError::DuplicateNodeId {
                    package: package_id,
                });
            }
        }

        let graph = Self {
            packages,
            nodes,
            workspace_members: workspace_members
                .into_iter()
                .map(|member| translated_package_id(&id_map, &member))
                .collect(),
        };
        graph.validate_structure()?;
        Ok(graph)
    }

    fn validate_structure(&self) -> Result<(), CargoGraphError> {
        for package_id in self.nodes.keys() {
            if !self.packages.contains_key(package_id) {
                return Err(CargoGraphError::NodePackageMissing {
                    package: package_id.clone(),
                });
            }
        }
        for package_id in self.packages.keys() {
            if !self.nodes.contains_key(package_id) {
                return Err(CargoGraphError::PackageNodeMissing {
                    package: package_id.clone(),
                });
            }
        }
        for member in &self.workspace_members {
            if !self.nodes.contains_key(member) {
                return Err(CargoGraphError::WorkspaceMemberMissing {
                    package: member.clone(),
                });
            }
        }
        for node in self.nodes.values() {
            for dependency in &node.dependencies {
                if !self.nodes.contains_key(&dependency.package) {
                    return Err(CargoGraphError::DependencyTargetMissing {
                        from: node.id.clone(),
                        dependency: dependency.name.clone(),
                        target: dependency.package.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn unique_framework_id(&self) -> Result<String, CargoGraphError> {
        let ids = self
            .packages
            .values()
            .filter(|package| package.name == FRAMEWORK_PACKAGE)
            .map(|package| package.id.clone())
            .collect::<Vec<_>>();
        match ids.as_slice() {
            [id] => Ok(id.clone()),
            _ => Err(CargoGraphError::FrameworkPackageCount { actual: ids }),
        }
    }

    fn dependency_closure(&self, root: &str) -> Result<BTreeSet<String>, CargoGraphError> {
        if !self.nodes.contains_key(root) {
            return Err(CargoGraphError::PackageNodeMissing {
                package: root.to_owned(),
            });
        }

        let mut closure = BTreeSet::new();
        let mut pending = vec![root.to_owned()];
        while let Some(package_id) = pending.pop() {
            if !closure.insert(package_id.clone()) {
                continue;
            }
            let node =
                self.nodes
                    .get(&package_id)
                    .ok_or_else(|| CargoGraphError::PackageNodeMissing {
                        package: package_id.clone(),
                    })?;
            pending.extend(
                node.dependencies
                    .iter()
                    .map(|dependency| dependency.package.clone()),
            );
        }
        Ok(closure)
    }

    fn edges(&self) -> BTreeSet<CargoGraphEdge> {
        self.nodes
            .values()
            .flat_map(|node| {
                node.dependencies
                    .iter()
                    .map(move |dependency| CargoGraphEdge {
                        from: node.id.clone(),
                        name: dependency.name.clone(),
                        to: dependency.package.clone(),
                        kinds: dependency.kinds.clone(),
                    })
            })
            .collect()
    }
}

/// Failure while parsing or structurally projecting Cargo metadata.
#[derive(Debug)]
pub enum CargoMetadataError {
    /// Cargo emitted invalid metadata JSON.
    Json(serde_json::Error),
    /// Cargo emitted a structurally inconsistent resolved graph.
    Graph(CargoGraphError),
}

impl fmt::Display for CargoMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "Cargo metadata is not valid JSON: {error}"),
            Self::Graph(error) => write!(formatter, "Cargo metadata graph is invalid: {error}"),
        }
    }
}

impl Error for CargoMetadataError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Graph(error) => Some(error),
        }
    }
}

/// A structural, provenance, alias, or bounded-difference graph violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CargoGraphError {
    /// Metadata did not contain a resolve graph.
    MissingResolve,
    /// Metadata repeated one package identifier.
    DuplicatePackageId {
        /// Repeated package identifier.
        package: String,
    },
    /// Metadata repeated one resolve-node identifier.
    DuplicateNodeId {
        /// Repeated resolve-node identifier.
        package: String,
    },
    /// A resolve node did not have a corresponding package record.
    NodePackageMissing {
        /// Resolve-node package identifier.
        package: String,
    },
    /// A package record did not have a corresponding resolve node.
    PackageNodeMissing {
        /// Package identifier missing from the resolve graph.
        package: String,
    },
    /// A workspace member did not have a corresponding resolve node.
    WorkspaceMemberMissing {
        /// Workspace-member package identifier.
        package: String,
    },
    /// A dependency edge targeted an unknown package identifier.
    DependencyTargetMissing {
        /// Depending package identifier.
        from: String,
        /// Dependency alias.
        dependency: String,
        /// Missing target package identifier.
        target: String,
    },
    /// The graph did not contain exactly one canonical framework package.
    FrameworkPackageCount {
        /// Sorted framework package identifiers found in the graph.
        actual: Vec<String>,
    },
    /// Workspace members did not contain an edge to the framework package.
    RootFrameworkEdgeCount {
        /// Canonical framework package identifier.
        framework: String,
        /// Sorted `root:alias` descriptions of edges that were found.
        actual: Vec<String>,
    },
    /// The unique workspace-to-framework edge used the wrong alias.
    RootAliasMismatch {
        /// Depending workspace package identifier.
        root: String,
        /// Required stable alias.
        expected: &'static str,
        /// Alias reported by Cargo.
        actual: String,
    },
    /// A reachable Omnius package had the wrong version.
    OmniusVersionMismatch {
        /// Resolved Omnius package identifier.
        package: String,
        /// Required release version.
        expected: String,
        /// Resolved package version.
        actual: String,
    },
    /// A reachable Omnius package had a noncanonical source or revision.
    OmniusSourceMismatch {
        /// Resolved Omnius package identifier.
        package: String,
        /// Required immutable Cargo source identifier.
        expected: String,
        /// Resolved source identifier, or `None` for a local package.
        actual: Option<String>,
    },
    /// Candidate resolution changed workspace membership.
    OutOfScopeWorkspaceChange {
        /// Workspace members before resolution.
        before: BTreeSet<String>,
        /// Workspace members after resolution.
        after: BTreeSet<String>,
    },
    /// Candidate resolution changed a package outside the framework closures.
    OutOfScopePackageChange {
        /// Unrelated package identifier that changed.
        package: String,
    },
    /// Candidate resolution changed features or edges outside the framework closures.
    OutOfScopeNodeChange {
        /// Unrelated resolve-node package identifier that changed.
        package: String,
    },
}

impl fmt::Display for CargoGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingResolve => formatter.write_str(
                "Cargo metadata did not include a resolve graph; run metadata without --no-deps",
            ),
            Self::DuplicatePackageId { package } => {
                write!(
                    formatter,
                    "Cargo metadata repeated package identifier `{package}`"
                )
            }
            Self::DuplicateNodeId { package } => write!(
                formatter,
                "Cargo metadata repeated resolve-node identifier `{package}`"
            ),
            Self::NodePackageMissing { package } => write!(
                formatter,
                "resolve node `{package}` has no corresponding package record"
            ),
            Self::PackageNodeMissing { package } => write!(
                formatter,
                "package `{package}` has no corresponding resolve node"
            ),
            Self::WorkspaceMemberMissing { package } => write!(
                formatter,
                "workspace member `{package}` has no corresponding resolve node"
            ),
            Self::DependencyTargetMissing {
                from,
                dependency,
                target,
            } => write!(
                formatter,
                "dependency `{dependency}` from `{from}` targets unknown package `{target}`"
            ),
            Self::FrameworkPackageCount { actual } => write!(
                formatter,
                "resolved graph must contain exactly one `{FRAMEWORK_PACKAGE}` package; found {} ({})",
                actual.len(),
                actual.join(", ")
            ),
            Self::RootFrameworkEdgeCount { framework, actual } => write!(
                formatter,
                "workspace members must contain at least one dependency edge to framework package `{framework}`; found {} ({})",
                actual.len(),
                actual.join(", ")
            ),
            Self::RootAliasMismatch {
                root,
                expected,
                actual,
            } => write!(
                formatter,
                "workspace package `{root}` must depend on the framework through alias `{expected}`, got `{actual}`"
            ),
            Self::OmniusVersionMismatch {
                package,
                expected,
                actual,
            } => write!(
                formatter,
                "reachable Omnius package `{package}` must have version `{expected}`, got `{actual}`"
            ),
            Self::OmniusSourceMismatch {
                package,
                expected,
                actual,
            } => write!(
                formatter,
                "reachable Omnius package `{package}` must have source `{expected}`, got `{}`",
                actual.as_deref().unwrap_or("<local/path>")
            ),
            Self::OutOfScopeWorkspaceChange { before, after } => write!(
                formatter,
                "framework resolution changed workspace members outside its mutable scope: before [{}], after [{}]",
                join_set(before),
                join_set(after)
            ),
            Self::OutOfScopePackageChange { package } => write!(
                formatter,
                "framework resolution changed unrelated package record `{package}`"
            ),
            Self::OutOfScopeNodeChange { package } => write!(
                formatter,
                "framework resolution changed unrelated features or dependency edges for `{package}`"
            ),
        }
    }
}

impl Error for CargoGraphError {}

/// Failure to execute, validate, or seal a Cargo resolution.
#[derive(Debug)]
pub enum CargoResolverError {
    /// The typed request contains an inconsistent mode or release identity.
    InvalidRequest(String),
    /// Cargo could not be started.
    Spawn {
        /// Exact shell-free invocation.
        command: CargoInvocation,
        /// Working directory supplied to Cargo.
        cwd: PathBuf,
        /// Process-spawn failure.
        source: io::Error,
    },
    /// Cargo exited unsuccessfully; stdout and stderr are captured as lossy diagnostic text.
    CommandFailed {
        /// Exact shell-free invocation.
        command: Box<CargoInvocation>,
        /// Working directory supplied to Cargo.
        cwd: PathBuf,
        /// Cargo exit status.
        status: ExitStatus,
        /// Captured standard output.
        stdout: String,
        /// Captured standard error.
        stderr: String,
    },
    /// Cargo emitted malformed or structurally invalid metadata.
    Metadata {
        /// Working directory used for the metadata command.
        cwd: PathBuf,
        /// Captured Cargo standard error.
        diagnostics: String,
        /// Metadata parsing or graph-projection failure.
        source: Box<CargoMetadataError>,
    },
    /// The resolved graph violated provenance or bounded-difference rules.
    Graph(CargoGraphError),
    /// `Cargo.lock` could not be inspected or read.
    LockfileIo {
        /// Lockfile path.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: io::Error,
    },
    /// `Cargo.lock` exists but is a symlink or another non-regular file type.
    LockfileNotRegular {
        /// Unsafe lockfile path.
        path: PathBuf,
    },
    /// The candidate was not seeded with the current project's exact lockfile bytes.
    CandidateLockMismatch {
        /// Current project lockfile path.
        current: PathBuf,
        /// Candidate project lockfile path.
        candidate: PathBuf,
    },
    /// A new-project request found a pre-existing lockfile.
    UnexpectedLockfile {
        /// Pre-existing candidate lockfile path.
        path: PathBuf,
    },
}

impl fmt::Display for CargoResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid Cargo resolver request: {message}")
            }
            Self::Spawn {
                command,
                cwd,
                source,
            } => write!(
                formatter,
                "failed to start `{command}` in `{}`: {source}",
                cwd.display()
            ),
            Self::CommandFailed {
                command,
                cwd,
                status,
                stdout,
                stderr,
            } => write!(
                formatter,
                "`{command}` failed in `{}` with status {status}; stdout: {}; stderr: {}",
                cwd.display(),
                diagnostic_text(stdout),
                diagnostic_text(stderr)
            ),
            Self::Metadata {
                cwd,
                diagnostics,
                source,
            } => write!(
                formatter,
                "could not parse `cargo metadata` output for `{}`: {source}; stderr: {}",
                cwd.display(),
                diagnostic_text(diagnostics)
            ),
            Self::Graph(error) => {
                write!(formatter, "resolved Cargo graph is not acceptable: {error}")
            }
            Self::LockfileIo { path, source } => write!(
                formatter,
                "could not read resolved lockfile `{}`: {source}",
                path.display()
            ),
            Self::LockfileNotRegular { path } => write!(
                formatter,
                "resolved lockfile `{}` must be a regular file and must not be a symlink",
                path.display()
            ),
            Self::CandidateLockMismatch { current, candidate } => write!(
                formatter,
                "candidate lockfile `{}` must initially match current lockfile `{}` byte-for-byte",
                candidate.display(),
                current.display()
            ),
            Self::UnexpectedLockfile { path } => write!(
                formatter,
                "new-project resolution requires a missing lockfile, but `{}` already exists",
                path.display()
            ),
        }
    }
}

impl Error for CargoResolverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spawn { source, .. } | Self::LockfileIo { source, .. } => Some(source),
            Self::Metadata { source, .. } => Some(source.as_ref()),
            Self::Graph(error) => Some(error),
            Self::InvalidRequest(_)
            | Self::CommandFailed { .. }
            | Self::LockfileNotRegular { .. }
            | Self::CandidateLockMismatch { .. }
            | Self::UnexpectedLockfile { .. } => None,
        }
    }
}

/// One shell-free Cargo invocation retained for actionable diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoInvocation {
    program: &'static str,
    arguments: Vec<OsString>,
}

impl fmt::Display for CargoInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.program)?;
        for argument in &self.arguments {
            formatter.write_str(" ")?;
            fmt::Debug::fmt(argument, formatter)?;
        }
        Ok(())
    }
}

struct CargoCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Deserialize)]
struct RawMetadata {
    packages: Vec<RawPackage>,
    resolve: Option<RawResolve>,
    workspace_members: Vec<String>,
    #[serde(default)]
    workspace_root: Option<String>,
}

#[derive(Deserialize)]
struct RawPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    #[serde(default)]
    manifest_path: Option<String>,
}

#[derive(Deserialize)]
struct RawResolve {
    nodes: Vec<RawNode>,
}

#[derive(Deserialize)]
struct RawNode {
    id: String,
    #[serde(default)]
    deps: Vec<RawDependency>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Deserialize)]
struct RawDependency {
    name: String,
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<RawDependencyKind>,
}

#[derive(Deserialize)]
struct RawDependencyKind {
    kind: Option<String>,
    target: Option<String>,
}

fn same_project(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn validate_request(request: &CargoResolverRequest) -> Result<(), CargoResolverError> {
    if request
        .current_project
        .as_deref()
        .is_some_and(|current| same_project(current, &request.candidate_project))
    {
        return Err(CargoResolverError::InvalidRequest(
            "current and candidate projects must be distinct so Cargo cannot mutate the destination before sealing"
                .to_owned(),
        ));
    }
    match &request.mode {
        CargoResolverMode::New => {
            if request.current_project.is_some() || request.before_release.is_some() {
                return Err(CargoResolverError::InvalidRequest(
                    "new-project resolution cannot have a current project or before-release identity"
                        .to_owned(),
                ));
            }
        }
        CargoResolverMode::LegacyCutover => {
            if request.current_project.is_none() || request.before_release.is_some() {
                return Err(CargoResolverError::InvalidRequest(
                    "legacy cutover requires a current project and no schema-2 before-release identity"
                        .to_owned(),
                ));
            }
        }
        CargoResolverMode::UpdateLocked => {
            if request.current_project.is_none() || request.before_release.is_none() {
                return Err(CargoResolverError::InvalidRequest(
                    "locked update requires a current project and before-release identity"
                        .to_owned(),
                ));
            }
            if request.before_release.as_ref() != Some(&request.target_release) {
                return Err(CargoResolverError::InvalidRequest(
                    "feature/profile lock updates require identical before and target release identities"
                        .to_owned(),
                ));
            }
        }
        CargoResolverMode::RevisionPrecise { revision } => {
            if request.current_project.is_none() || request.before_release.is_none() {
                return Err(CargoResolverError::InvalidRequest(
                    "revision update requires a current project and before-release identity"
                        .to_owned(),
                ));
            }
            if revision != request.target_release.revision() {
                return Err(CargoResolverError::InvalidRequest(format!(
                    "precise revision `{revision}` does not match target release revision `{}`",
                    request.target_release.revision()
                )));
            }
        }
    }
    Ok(())
}

fn validate_lockfile_inputs(request: &CargoResolverRequest) -> Result<(), CargoResolverError> {
    let candidate_lockfile = request.candidate_project.join("Cargo.lock");
    match &request.mode {
        CargoResolverMode::New => match fs::symlink_metadata(&candidate_lockfile) {
            Ok(_) => {
                return Err(CargoResolverError::UnexpectedLockfile {
                    path: candidate_lockfile,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CargoResolverError::LockfileIo {
                    path: candidate_lockfile,
                    source,
                });
            }
        },
        CargoResolverMode::LegacyCutover
        | CargoResolverMode::UpdateLocked
        | CargoResolverMode::RevisionPrecise { .. } => {
            let candidate = read_regular_lockfile(&request.candidate_project)?;
            if let Some(current_project) = &request.current_project {
                let current = read_regular_lockfile(current_project)?;
                if current != candidate {
                    return Err(CargoResolverError::CandidateLockMismatch {
                        current: current_project.join("Cargo.lock"),
                        candidate: candidate_lockfile,
                    });
                }
            }
        }
    }
    Ok(())
}

fn unlocked_metadata(project: &Path, offline: bool) -> Result<CargoGraph, CargoResolverError> {
    let output = run_cargo(
        project,
        cargo_args(&["metadata", "--format-version", "1"], offline),
    )?;
    CargoGraph::from_metadata_json(&output.stdout).map_err(|source| CargoResolverError::Metadata {
        cwd: project.to_owned(),
        diagnostics: String::from_utf8_lossy(&output.stderr).into_owned(),
        source: Box::new(source),
    })
}

fn locked_metadata(project: &Path, offline: bool) -> Result<CargoGraph, CargoResolverError> {
    let output = run_cargo(
        project,
        cargo_args(&["metadata", "--format-version", "1", "--locked"], offline),
    )?;
    CargoGraph::from_metadata_json(&output.stdout).map_err(|source| CargoResolverError::Metadata {
        cwd: project.to_owned(),
        diagnostics: String::from_utf8_lossy(&output.stderr).into_owned(),
        source: Box::new(source),
    })
}

fn run_cargo(
    project: &Path,
    arguments: Vec<OsString>,
) -> Result<CargoCommandOutput, CargoResolverError> {
    let invocation = CargoInvocation {
        program: CARGO,
        arguments,
    };
    let output = Command::new(invocation.program)
        .args(&invocation.arguments)
        .current_dir(project)
        .output()
        .map_err(|source| CargoResolverError::Spawn {
            command: invocation.clone(),
            cwd: project.to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(CargoResolverError::CommandFailed {
            command: Box::new(invocation),
            cwd: project.to_owned(),
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(CargoCommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
fn cargo_args(arguments: &[&str], offline: bool) -> Vec<OsString> {
    let mut result = arguments
        .iter()
        .map(|argument| OsString::from(*argument))
        .collect::<Vec<_>>();
    if offline {
        result.push(OsString::from("--offline"));
    }
    result
}

fn cargo_update_args(version: &str, precise: Option<&str>, offline: bool) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("update"),
        OsString::from("-p"),
        OsString::from(format!("{FRAMEWORK_PACKAGE}@{version}")),
    ];
    if let Some(revision) = precise {
        arguments.push(OsString::from("--precise"));
        arguments.push(OsString::from(revision));
    }
    if offline {
        arguments.push(OsString::from("--offline"));
    }
    arguments
}

fn read_regular_lockfile(project: &Path) -> Result<Vec<u8>, CargoResolverError> {
    let path = project.join("Cargo.lock");
    let mut file = open_regular_lockfile(&path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CargoResolverError::LockfileIo { path, source })?;
    Ok(bytes)
}

fn open_regular_lockfile(path: &Path) -> Result<File, CargoResolverError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CargoResolverError::LockfileIo {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(CargoResolverError::LockfileNotRegular {
            path: path.to_owned(),
        });
    }

    let descriptor = open(path, LOCKFILE_READ_FLAGS, Mode::empty()).map_err(|error| {
        CargoResolverError::LockfileIo {
            path: path.to_owned(),
            source: io::Error::from_raw_os_error(error.raw_os_error()),
        }
    })?;
    let opened_metadata = fstat(&descriptor).map_err(|error| CargoResolverError::LockfileIo {
        path: path.to_owned(),
        source: io::Error::from_raw_os_error(error.raw_os_error()),
    })?;
    if FileType::from_raw_mode(opened_metadata.st_mode) != FileType::RegularFile {
        return Err(CargoResolverError::LockfileNotRegular {
            path: path.to_owned(),
        });
    }
    Ok(File::from(descriptor))
}

fn normalized_package_id(package: &RawPackage, workspace_root: Option<&Path>) -> String {
    if package.source.is_none()
        && let (Some(workspace_root), Some(manifest_path)) =
            (workspace_root, package.manifest_path.as_deref())
        && let Some(relative_path) = lexical_relative_path(workspace_root, Path::new(manifest_path))
    {
        let stable_path = relative_path.to_string_lossy().replace('\\', "/");
        return format!(
            "workspace+{stable_path}#{}@{}",
            package.name, package.version
        );
    }
    package.id.clone()
}
fn lexical_relative_path(base: &Path, target: &Path) -> Option<PathBuf> {
    let base_components = base.components().collect::<Vec<_>>();
    let target_components = target.components().collect::<Vec<_>>();
    let common = base_components
        .iter()
        .zip(&target_components)
        .take_while(|(left, right)| left == right)
        .count();

    let mut relative = PathBuf::new();
    for component in &base_components[common..] {
        match component {
            std::path::Component::Normal(_) => relative.push(".."),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => return None,
        }
    }
    for component in &target_components[common..] {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => return None,
            _ => relative.push(component.as_os_str()),
        }
    }
    Some(relative)
}

fn translated_package_id(id_map: &BTreeMap<String, String>, package_id: &str) -> String {
    id_map
        .get(package_id)
        .cloned()
        .unwrap_or_else(|| package_id.to_owned())
}

fn canonical_git_source(release: &ReleaseIdentity) -> String {
    format!(
        "git+{}?rev={}#{}",
        release.repository(),
        release.revision(),
        release.revision()
    )
}

fn cargo_names_equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left.bytes().zip(right.bytes()).all(|(left, right)| {
            normalize_cargo_name_byte(left) == normalize_cargo_name_byte(right)
        })
}

const fn normalize_cargo_name_byte(byte: u8) -> u8 {
    if byte == b'-' { b'_' } else { byte }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum ComparableTarget<'a> {
    Fixed(&'a str),
    MutablePackage(&'a str),
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct ComparableDependency<'a> {
    name: &'a str,
    target: ComparableTarget<'a>,
    kinds: &'a BTreeSet<CargoDependencyKind>,
}

#[derive(Clone, Copy)]
struct LegacyBoundary<'a> {
    before_ignored: &'a BTreeSet<String>,
    after_ignored: &'a BTreeSet<String>,
    after_framework: &'a str,
}

fn nodes_equal_outside_mutable_closures<'a>(
    before_graph: &'a CargoGraph,
    before: Option<&'a CargoNode>,
    after_graph: &'a CargoGraph,
    after: Option<&'a CargoNode>,
    mutable_ids: &BTreeSet<String>,
    legacy_boundary: Option<LegacyBoundary<'_>>,
) -> Result<bool, CargoGraphError> {
    match (before, after) {
        (Some(before), Some(after)) => {
            if before.features != after.features {
                return Ok(false);
            }
            let mut legacy_root = false;
            if let Some(boundary) = legacy_boundary {
                let had_legacy_boundary = before.dependencies.iter().any(|dependency| {
                    boundary
                        .before_ignored
                        .contains(dependency.package.as_str())
                });
                let mut replacements = after.dependencies.iter().filter(|dependency| {
                    boundary.after_ignored.contains(dependency.package.as_str())
                });
                let replacement = replacements.next();
                if replacements.next().is_some()
                    || match (had_legacy_boundary, replacement) {
                        (true, Some(replacement)) => {
                            replacement.package != boundary.after_framework
                                || !cargo_names_equal(
                                    replacement.name.as_str(),
                                    ROOT_FRAMEWORK_ALIAS,
                                )
                                || !canonical_service_kit_kinds(&replacement.kinds)
                        }
                        (false, None) => false,
                        (true, None) | (false, Some(_)) => true,
                    }
                {
                    return Ok(false);
                }
                if had_legacy_boundary {
                    for dependency in &after.dependencies {
                        let package =
                            after_graph
                                .packages
                                .get(&dependency.package)
                                .ok_or_else(|| CargoGraphError::NodePackageMissing {
                                    package: dependency.package.clone(),
                                })?;
                        if dependency.package != boundary.after_framework
                            && package.name.starts_with("omnius-")
                        {
                            return Ok(false);
                        }
                    }
                    legacy_root = true;
                }
            }
            let before_dependencies = comparable_dependencies(
                before_graph,
                before,
                mutable_ids,
                legacy_boundary.map(|boundary| boundary.before_ignored),
            )?;
            let after_dependencies = comparable_dependencies(
                after_graph,
                after,
                mutable_ids,
                legacy_boundary.map(|boundary| boundary.after_ignored),
            )?;
            if before_dependencies == after_dependencies {
                return Ok(true);
            }
            Ok(legacy_root
                && legacy_toml_normal_kind_removed(&before_dependencies, &after_dependencies))
        }
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
    }
}

fn canonical_service_kit_kinds(kinds: &BTreeSet<CargoDependencyKind>) -> bool {
    let mut normal = false;
    let mut development = false;
    for kind in kinds {
        match (kind.kind.as_deref(), kind.target.as_deref()) {
            (None, None) => normal = true,
            (Some("dev"), None) => development = true,
            _ => return false,
        }
    }
    normal && development
}

fn legacy_toml_normal_kind_removed<'a>(
    before: &BTreeSet<ComparableDependency<'a>>,
    after: &BTreeSet<ComparableDependency<'a>>,
) -> bool {
    let mut before_toml_edges = before
        .iter()
        .filter(|dependency| cargo_names_equal(dependency.name, "toml"));
    let mut after_toml_edges = after
        .iter()
        .filter(|dependency| cargo_names_equal(dependency.name, "toml"));
    let (Some(before_toml), Some(after_toml)) = (before_toml_edges.next(), after_toml_edges.next())
    else {
        return false;
    };
    if before_toml_edges.next().is_some()
        || after_toml_edges.next().is_some()
        || before_toml.target != after_toml.target
        || !normal_and_build_kinds(before_toml.kinds)
        || !build_only_kinds(after_toml.kinds)
    {
        return false;
    }
    before
        .iter()
        .filter(|dependency| !cargo_names_equal(dependency.name, "toml"))
        .eq(after
            .iter()
            .filter(|dependency| !cargo_names_equal(dependency.name, "toml")))
}

fn normal_and_build_kinds(kinds: &BTreeSet<CargoDependencyKind>) -> bool {
    let mut normal = false;
    let mut build = false;
    for kind in kinds {
        match (kind.kind.as_deref(), kind.target.as_deref()) {
            (None, None) => normal = true,
            (Some("build"), None) => build = true,
            _ => return false,
        }
    }
    normal && build
}

fn build_only_kinds(kinds: &BTreeSet<CargoDependencyKind>) -> bool {
    let Some(kind) = kinds.iter().next() else {
        return false;
    };
    kinds.len() == 1 && kind.kind.as_deref() == Some("build") && kind.target.as_deref().is_none()
}

fn comparable_dependencies<'a>(
    graph: &'a CargoGraph,
    node: &'a CargoNode,
    mutable_ids: &BTreeSet<String>,
    ignored_boundary_ids: Option<&BTreeSet<String>>,
) -> Result<BTreeSet<ComparableDependency<'a>>, CargoGraphError> {
    node.dependencies
        .iter()
        .filter(|dependency| {
            !ignored_boundary_ids
                .is_some_and(|ignored| ignored.contains(dependency.package.as_str()))
        })
        .map(|dependency| {
            let target = if mutable_ids.contains(dependency.package.as_str()) {
                let package = graph.packages.get(&dependency.package).ok_or_else(|| {
                    CargoGraphError::NodePackageMissing {
                        package: dependency.package.clone(),
                    }
                })?;
                ComparableTarget::MutablePackage(package.name.as_str())
            } else {
                ComparableTarget::Fixed(dependency.package.as_str())
            };
            Ok(ComparableDependency {
                name: dependency.name.as_str(),
                target,
                kinds: &dependency.kinds,
            })
        })
        .collect()
}

fn diagnostic_text(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "<empty>"
    } else {
        trimmed
    }
}

fn join_set(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{Value, json};

    use super::{
        CargoGraph, CargoGraphError, CargoMetadataError, cargo_update_args, read_regular_lockfile,
    };
    use crate::release::{CANONICAL_REPOSITORY, ReleaseIdentity};

    const OLD_REVISION: &str = "1111111111111111111111111111111111111111";
    const NEW_REVISION: &str = "2222222222222222222222222222222222222222";

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn framework_validation_accepts_canonical_alias_and_reachable_packages() {
        let release = release(OLD_REVISION);
        let graph = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));

        let framework = graph.validate_framework(&release);

        assert_eq!(framework, Ok(kit_id(OLD_REVISION)));
    }

    #[test]
    fn framework_validation_accepts_multiple_canonical_workspace_aliases() {
        let release = release(OLD_REVISION);
        let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
        let kit = kit_id(OLD_REVISION);
        let Some(packages) = document["packages"].as_array_mut() else {
            panic!("packages must be an array");
        };
        packages.push(json!({
            "id": "worker",
            "name": "example-worker",
            "version": "0.1.0",
            "source": null
        }));
        let Some(workspace_members) = document["workspace_members"].as_array_mut() else {
            panic!("workspace members must be an array");
        };
        workspace_members.push(json!("worker"));
        let Some(resolve_nodes) = document["resolve"]["nodes"].as_array_mut() else {
            panic!("resolve nodes must be an array");
        };
        resolve_nodes.push(json!({
            "id": "worker",
            "deps": [
                {
                    "name": "service_kit",
                    "pkg": kit,
                    "dep_kinds": [{ "kind": null, "target": null }]
                }
            ],
            "features": []
        }));

        assert_eq!(
            parse_graph(&document).validate_framework(&release),
            Ok(kit_id(OLD_REVISION))
        );
    }

    #[test]
    fn framework_validation_rejects_noncanonical_reachable_omnius_source() {
        let release = release(OLD_REVISION);
        let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
        document["packages"][2]["source"] = Value::Null;
        let graph = parse_graph(&document);

        let error = graph.validate_framework(&release);

        assert!(matches!(
            error,
            Err(CargoGraphError::OmniusSourceMismatch { package, actual: None, .. })
                if package == runtime_id(OLD_REVISION)
        ));
    }

    #[test]
    fn framework_validation_rejects_wrong_resolved_revision() {
        let release = release(OLD_REVISION);
        let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
        document["packages"][1]["source"] = json!(source(NEW_REVISION));
        let graph = parse_graph(&document);

        let error = graph.validate_framework(&release);

        assert!(matches!(
            error,
            Err(CargoGraphError::OmniusSourceMismatch { package, .. })
                if package == kit_id(OLD_REVISION)
        ));
    }

    #[test]
    fn framework_validation_rejects_wrong_root_alias() {
        let release = release(OLD_REVISION);
        let graph = parse_graph(&metadata(OLD_REVISION, "framework", "registry-one", false));

        let error = graph.validate_framework(&release);

        assert!(matches!(
            error,
            Err(CargoGraphError::RootAliasMismatch { actual, .. }) if actual == "framework"
        ));
    }

    #[test]
    fn bounded_difference_allows_changes_inside_old_and_new_framework_closures() {
        let before_release = release(OLD_REVISION);
        let after_release = release(NEW_REVISION);
        let before = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        let after = parse_graph(&metadata(
            NEW_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        assert!(before.validate_framework(&before_release).is_ok());
        assert!(after.validate_framework(&after_release).is_ok());

        let difference = before.bounded_framework_difference(&after);

        assert!(matches!(
            difference,
            Ok(difference)
                if difference.added_packages.contains(&kit_id(NEW_REVISION))
                    && difference.removed_packages.contains(&kit_id(OLD_REVISION))
        ));
    }

    #[test]
    fn legacy_cutover_allows_direct_framework_edges_to_collapse_behind_service_kit() {
        let mut before_document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
        before_document["resolve"]["nodes"][0]["deps"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("application dependencies must be an array"))
            .push(json!({
                "name": "omnius_runtime",
                "pkg": runtime_id(OLD_REVISION),
                "dep_kinds": [{ "kind": null, "target": null }]
            }));
        let before = parse_graph(&before_document);
        let after = parse_graph(&thin_metadata(NEW_REVISION, "registry-one"));

        let difference = before.bounded_difference_from_roots(
            &after,
            &kit_id(OLD_REVISION),
            &kit_id(NEW_REVISION),
            true,
        );

        assert!(difference.is_ok());
    }

    #[test]
    fn legacy_short_link_fixture_allows_obsolete_toml_normal_kind_removal() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/legacy-short-link-resolver-graphs.json"
        ))
        .unwrap_or_else(|error| panic!("legacy resolver fixture must be valid JSON: {error}"));
        let before = parse_graph(&fixture["before"]);
        let after = parse_graph(&fixture["after"]);

        let difference =
            before.bounded_difference_from_roots(&after, "legacy-kit", "git-kit", true);

        assert!(difference.is_ok());
    }

    #[test]
    fn legacy_cutover_rejects_application_external_edge_changes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/legacy-short-link-resolver-graphs.json"
        ))
        .unwrap_or_else(|error| panic!("legacy resolver fixture must be valid JSON: {error}"));
        let before = parse_graph(&fixture["before"]);
        let mut after_document = fixture["after"].clone();
        after_document["resolve"]["nodes"][0]["deps"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("application dependencies must be an array"))
            .retain(|dependency| dependency["name"] != "serde");
        let after = parse_graph(&after_document);

        let error = before.bounded_difference_from_roots(&after, "legacy-kit", "git-kit", true);

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
        ));
    }

    #[test]
    fn legacy_cutover_still_rejects_unrelated_workspace_edge_changes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/legacy-short-link-resolver-graphs.json"
        ))
        .unwrap_or_else(|error| panic!("legacy resolver fixture must be valid JSON: {error}"));
        let before = parse_graph(&fixture["before"]);
        let mut after_document = fixture["after"].clone();
        after_document["resolve"]["nodes"][1]["deps"] = json!([]);
        let after = parse_graph(&after_document);

        let error = before.bounded_difference_from_roots(&after, "legacy-kit", "git-kit", true);

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "helper"
        ));
    }

    #[test]
    fn legacy_cutover_rejects_candidate_direct_omnius_edges() {
        let before = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        let mut after_document = thin_metadata(NEW_REVISION, "registry-one");
        after_document["resolve"]["nodes"][0]["deps"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("application dependencies must be an array"))
            .push(json!({
                "name": "omnius_runtime",
                "pkg": runtime_id(NEW_REVISION),
                "dep_kinds": [{ "kind": null, "target": null }]
            }));
        let after = parse_graph(&after_document);

        let error = before.bounded_difference_from_roots(
            &after,
            &kit_id(OLD_REVISION),
            &kit_id(NEW_REVISION),
            true,
        );

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
        ));
    }

    #[test]
    fn legacy_cutover_requires_the_canonical_service_kit_replacement_edge() {
        let before = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        for replacement in [
            json!([{
                "name": "registry_dependency",
                "pkg": "registry-one",
                "dep_kinds": [{ "kind": null, "target": null }]
            }]),
            json!([
                {
                    "name": "framework",
                    "pkg": kit_id(NEW_REVISION),
                    "dep_kinds": [
                        { "kind": null, "target": null },
                        { "kind": "dev", "target": null }
                    ]
                },
                {
                    "name": "registry_dependency",
                    "pkg": "registry-one",
                    "dep_kinds": [{ "kind": null, "target": null }]
                }
            ]),
        ] {
            let mut after_document = thin_metadata(NEW_REVISION, "registry-one");
            after_document["resolve"]["nodes"][0]["deps"] = replacement;
            let after = parse_graph(&after_document);

            let error = before.bounded_difference_from_roots(
                &after,
                &kit_id(OLD_REVISION),
                &kit_id(NEW_REVISION),
                true,
            );

            assert!(matches!(
                error,
                Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
            ));
        }
    }

    #[test]
    fn bounded_difference_normalizes_workspace_packages_across_stage_paths() {
        let before = parse_graph(&relocated_metadata(
            OLD_REVISION,
            "/tmp/current-service-project",
        ));
        let after = parse_graph(&relocated_metadata(
            NEW_REVISION,
            "/tmp/candidate-service-project",
        ));

        let difference = before.bounded_framework_difference(&after);

        assert!(difference.is_ok());
    }

    #[test]
    fn bounded_difference_rejects_framework_boundary_kind_change() {
        let before = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        let mut document = metadata(NEW_REVISION, "service_kit", "registry-one", false);
        document["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = json!("dev");
        let after = parse_graph(&document);

        let error = before.bounded_framework_difference(&after);

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
        ));
    }

    #[test]
    fn bounded_difference_normalizes_external_local_packages_across_stage_paths() {
        let before = parse_graph(&external_local_metadata(
            OLD_REVISION,
            "/tmp/current/service",
            "/tmp/current/shared",
        ));
        let after = parse_graph(&external_local_metadata(
            NEW_REVISION,
            "/tmp/candidate/service",
            "/tmp/candidate/shared",
        ));

        let difference = before.bounded_framework_difference(&after);

        assert!(difference.is_ok());
    }

    #[test]
    fn bounded_difference_rejects_unrelated_package_identity_change() {
        let before = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        let after = parse_graph(&metadata(NEW_REVISION, "service_kit", "registry-one", true));

        let error = before.bounded_framework_difference(&after);

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopePackageChange { package })
                if package == "registry-one"
        ));
    }

    #[test]
    fn bounded_difference_rejects_unrelated_edge_change() {
        let before = parse_graph(&metadata(
            OLD_REVISION,
            "service_kit",
            "registry-one",
            false,
        ));
        let mut document = metadata(NEW_REVISION, "service_kit", "registry-one", false);
        document["resolve"]["nodes"][0]["deps"] = json!([]);
        let after = parse_graph(&document);

        let error = before.bounded_framework_difference(&after);

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
        ));
    }

    #[test]
    fn metadata_projection_rejects_dependency_to_unknown_package() {
        let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
        document["resolve"]["nodes"][1]["deps"][0]["pkg"] = json!("missing");

        let error = CargoGraph::from_metadata_json(document.to_string().as_bytes());

        assert!(matches!(
            error,
            Err(CargoMetadataError::Graph(
                CargoGraphError::DependencyTargetMissing { target, .. }
            )) if target == "missing"
        ));
    }

    #[test]
    fn precise_offline_update_selects_the_locked_framework_version() {
        let arguments = cargo_update_args("0.2.0", Some(NEW_REVISION), true);

        assert_eq!(
            arguments,
            vec![
                OsString::from("update"),
                OsString::from("-p"),
                OsString::from("omnius-service-kit@0.2.0"),
                OsString::from("--precise"),
                OsString::from(NEW_REVISION),
                OsString::from("--offline"),
            ]
        );
    }

    #[test]
    fn lockfile_reader_preserves_exact_binary_bytes() {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let project = std::env::temp_dir().join(format!(
            "omnius-cargo-resolver-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&project)
            .unwrap_or_else(|error| panic!("test directory must be creatable: {error}"));
        let expected = b"version = 4\n\xff\x00lock-bytes\n";
        fs::write(project.join("Cargo.lock"), expected)
            .unwrap_or_else(|error| panic!("test lockfile must be writable: {error}"));

        let actual = read_regular_lockfile(&project);
        let _ = fs::remove_dir_all(project);
        match actual {
            Ok(bytes) => assert_eq!(bytes, expected),
            Err(error) => panic!("test lockfile must be readable: {error}"),
        }
    }

    fn release(revision: &str) -> ReleaseIdentity {
        ReleaseIdentity::new("0.3.0", CANONICAL_REPOSITORY, revision)
            .unwrap_or_else(|error| panic!("test release identity must be valid: {error}"))
    }

    fn parse_graph(document: &Value) -> CargoGraph {
        CargoGraph::from_metadata_json(document.to_string().as_bytes())
            .unwrap_or_else(|error| panic!("test metadata must be valid: {error}"))
    }

    fn source(revision: &str) -> String {
        format!("git+{CANONICAL_REPOSITORY}?rev={revision}#{revision}")
    }

    fn kit_id(revision: &str) -> String {
        format!("git-kit-{revision}")
    }

    fn runtime_id(revision: &str) -> String {
        format!("git-runtime-{revision}")
    }

    fn external_local_metadata(revision: &str, root: &str, shared: &str) -> Value {
        let mut document = relocated_metadata(revision, root);
        let dependency_id = format!("file://{shared}#registry-dependency@1.0.0");
        document["packages"][3]["id"] = json!(dependency_id.clone());
        document["packages"][3]["source"] = Value::Null;
        document["packages"][3]["manifest_path"] = json!(format!("{shared}/Cargo.toml"));
        document["resolve"]["nodes"][0]["deps"][1]["pkg"] = json!(dependency_id.clone());
        document["resolve"]["nodes"][3]["id"] = json!(dependency_id);
        document
    }

    fn thin_metadata(revision: &str, registry_id: &str) -> Value {
        let mut document = metadata(revision, "service_kit", registry_id, false);
        document["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = json!([
            { "kind": null, "target": null },
            { "kind": "dev", "target": null }
        ]);
        document
    }

    fn relocated_metadata(revision: &str, root: &str) -> Value {
        let mut document = metadata(revision, "service_kit", "registry-one", false);
        let application_id = format!("file://{root}#example-service@0.1.0");
        document["workspace_root"] = json!(root);
        document["packages"][0]["id"] = json!(application_id.clone());
        document["packages"][0]["manifest_path"] = json!(format!("{root}/Cargo.toml"));
        document["workspace_members"][0] = json!(application_id.clone());
        document["resolve"]["nodes"][0]["id"] = json!(application_id);
        document
    }

    fn metadata(
        revision: &str,
        alias: &str,
        registry_id: &str,
        changed_registry_identity: bool,
    ) -> Value {
        let kit = kit_id(revision);
        let runtime = runtime_id(revision);
        let registry_version = if changed_registry_identity {
            "2.0.0"
        } else {
            "1.0.0"
        };
        json!({
            "packages": [
                { "id": "app", "name": "example-service", "version": "0.1.0", "source": null },
                { "id": kit.clone(), "name": "omnius-service-kit", "version": "0.3.0", "source": source(revision) },
                { "id": runtime.clone(), "name": "omnius-runtime", "version": "0.3.0", "source": source(revision) },
                { "id": registry_id, "name": "registry-dependency", "version": registry_version, "source": "registry+https://github.com/rust-lang/crates.io-index" }
            ],
            "workspace_members": ["app"],
            "resolve": {
                "nodes": [
                    {
                        "id": "app",
                        "deps": [
                            { "name": alias, "pkg": kit.clone(), "dep_kinds": [{ "kind": null, "target": null }] },
                            { "name": "registry_dependency", "pkg": registry_id, "dep_kinds": [{ "kind": null, "target": null }] }
                        ],
                        "features": []
                    },
                    {
                        "id": kit,
                        "deps": [
                            { "name": "omnius_runtime", "pkg": runtime.clone(), "dep_kinds": [{ "kind": null, "target": null }] }
                        ],
                        "features": ["http"]
                    },
                    {
                        "id": runtime,
                        "deps": [],
                        "features": []
                    },
                    {
                        "id": registry_id,
                        "deps": [],
                        "features": []
                    }
                ]
            }
        })
    }
}
