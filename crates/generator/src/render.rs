use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use minijinja::{AutoEscape, Environment, UndefinedBehavior, context};

use crate::{
    MANAGED_MARKER_VERSION, PROJECT_STATE_PATH, PROJECT_STATE_SCHEMA_VERSION, ProfileError,
    ReleaseIdentity,
    application_templates::{application_template, validate_application_template_catalog},
    cargo_resolver::{
        CargoLockfileResolver, CargoResolverError, CargoResolverRequest, LockfileResolver,
    },
    lifecycle::{LifecycleError, OwnedSiblingStage, write_project_file},
    manager::{
        MANAGER_DERIVED_PATHS, compose_initial_profile, normalize_next_state,
        render_derived_with_retained_volumes, retain_selected_compose_volumes,
    },
    provenance::inspect_project_provenance,
    resolve_profile,
    state::{
        ManagedRegionRecord, OwnershipKind, OwnershipRecord, ProfileSelection, ProjectState,
        SelectedModule, SelectedProvider, sha256_hex,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ownership {
    Kit,
    Application,
    Derived,
}

#[derive(Clone, Copy)]
struct TemplateFile {
    path: &'static str,
    source: &'static str,
    ownership: Ownership,
}

macro_rules! template {
    ($path:literal, $source:literal, $ownership:ident) => {
        TemplateFile {
            path: $path,
            source: include_str!($source),
            ownership: Ownership::$ownership,
        }
    };
}
const TEMPLATE_FILES: &[TemplateFile] = &[
    template!(
        ".dockerignore",
        "../../../templates/base-service/.dockerignore",
        Kit
    ),
    template!(
        ".gitignore",
        "../../../templates/base-service/.gitignore",
        Kit
    ),
    template!(
        "Cargo.toml",
        "../../../templates/base-service/Cargo.toml",
        Application
    ),
    template!(
        "README.md",
        "../../../templates/base-service/README.md",
        Application
    ),
    template!(
        "apps/service/Cargo.toml",
        "../../../templates/base-service/apps/service/Cargo.toml",
        Application
    ),
    template!(
        "apps/service/build.rs",
        "../../../templates/base-service/apps/service/build.rs",
        Kit
    ),
    template!(
        "apps/service/src/application.rs",
        "../../../templates/base-service/apps/service/src/application.rs",
        Application
    ),
    template!(
        "apps/service/src/composition.rs",
        "../../../templates/base-service/apps/service/src/composition.rs",
        Application
    ),
    template!(
        "apps/service/src/lib.rs",
        "../../../templates/base-service/apps/service/src/lib.rs",
        Kit
    ),
    template!(
        "apps/service/src/main.rs",
        "../../../templates/base-service/apps/service/src/main.rs",
        Kit
    ),
    template!(
        "apps/service/tests/http.rs",
        "../../../templates/base-service/apps/service/tests/http.rs",
        Kit
    ),
    template!(
        "config/base.toml",
        "../../../templates/base-service/config/base.toml",
        Kit
    ),
    template!(
        "config/local.toml",
        "../../../templates/base-service/config/local.toml",
        Kit
    ),
    template!(
        "config/profile.toml",
        "../../../templates/base-service/config/profile.toml",
        Kit
    ),
    template!(
        "docs/operations.md",
        "../../../templates/base-service/docs/operations.md",
        Kit
    ),
    template!(
        "ops/profile.toml",
        "../../../templates/base-service/ops/profile.toml",
        Kit
    ),
];

/// Inputs for deterministic base-service expansion.
#[derive(Clone, Copy, Debug)]
pub struct RenderRequest<'a> {
    /// Canonical lowercase kebab-case Cargo package and service name.
    pub service_name: &'a str,
    /// One of the ten authoritative base profile identifiers.
    pub profile: &'a str,
    /// Destination that must not exist before atomic publication.
    pub destination: &'a Path,
    /// Immutable framework release referenced by the generated workspace.
    pub release_identity: &'a ReleaseIdentity,
}

/// Result of atomically publishing a newly resolved project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderOutcome {
    /// Number of canonical rendered files, including `Cargo.lock`.
    pub files: usize,
}

/// Failure to validate or safely expand a base service.
#[derive(Debug)]
pub enum RenderError {
    /// The requested service name was not canonical Cargo kebab case.
    InvalidServiceName,
    /// The selected base profile was invalid or unknown.
    Profile(ProfileError),
    /// The new-project destination already exists, whether empty or nonempty.
    DestinationExists(PathBuf),
    /// A bundled template could not be evaluated.
    Template(minijinja::Error),
    /// Canonical manager-owned state or artifact generation failed.
    Canonical(String),
    /// Cargo failed to resolve the staged new project.
    Resolver(CargoResolverError),
    /// Generated manifests or effective Cargo configuration violate provenance policy.
    Provenance(String),
    /// Sibling staging or atomic publication failed.
    Lifecycle(LifecycleError),
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceName => formatter.write_str(
                "service name must start with a lowercase ASCII letter and contain only lowercase ASCII letters, digits, and internal hyphens",
            ),
            Self::Profile(error) => write!(formatter, "cannot resolve service profile: {error}"),
            Self::DestinationExists(path) => write!(
                formatter,
                "new-project destination already exists: {}",
                path.display()
            ),
            Self::Canonical(message) => {
                write!(formatter, "cannot canonicalize generated profile: {message}")
            }
            Self::Template(error) => write!(formatter, "base service template failed: {error}"),
            Self::Resolver(error) => write!(formatter, "Cargo resolution failed: {error}"),
            Self::Provenance(message) => {
                write!(formatter, "generated project provenance is invalid: {message}")
            }
            Self::Lifecycle(error) => write!(formatter, "new-project lifecycle failed: {error}"),
        }
    }
}

impl Error for RenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Profile(error) => Some(error),
            Self::Template(error) => Some(error),
            Self::Resolver(error) => Some(error),
            Self::Lifecycle(error) => Some(error),
            Self::InvalidServiceName
            | Self::DestinationExists(_)
            | Self::Canonical(_)
            | Self::Provenance(_) => None,
        }
    }
}

impl From<ProfileError> for RenderError {
    fn from(error: ProfileError) -> Self {
        Self::Profile(error)
    }
}

/// Renders, resolves, and atomically publishes a new service with the production resolver.
///
/// The destination must not exist. Cargo runs only in an owned sibling stage, and a successful
/// project appears at the destination through one no-replace rename.
///
/// # Errors
///
/// Returns [`RenderError`] for invalid inputs, an existing destination, staging or template
/// failures, Cargo resolution failures, or atomic publication failures.
///
pub fn render_project(request: RenderRequest<'_>) -> Result<RenderOutcome, RenderError> {
    render_project_with_options(request, false)
}

/// Renders and publishes a new service with the production resolver and explicit offline mode.
///
/// # Errors
///
/// Returns [`RenderError`] under the same conditions as [`render_project`].
pub fn render_project_with_options(
    request: RenderRequest<'_>,
    offline: bool,
) -> Result<RenderOutcome, RenderError> {
    render_project_with_resolver(request, offline, &CargoLockfileResolver)
}

/// Renders, resolves, and atomically publishes a new service using an injected resolver.
///
/// This is the deterministic testing seam for the same lifecycle used by [`render_project`].
///
/// # Errors
///
/// Returns [`RenderError`] under the same conditions as [`render_project`].
pub fn render_project_with_resolver<R: LockfileResolver + ?Sized>(
    request: RenderRequest<'_>,
    offline: bool,
    lockfile_resolver: &R,
) -> Result<RenderOutcome, RenderError> {
    let staging_area =
        OwnedSiblingStage::create_for_new(request.destination).map_err(|error| match error {
            LifecycleError::DestinationExists(path) => RenderError::DestinationExists(path),
            other => RenderError::Lifecycle(other),
        })?;
    validate_service_name(request.service_name)?;
    let profile_selection = resolve_profile(request.profile)?;
    let mut rendered = render_files(
        request.service_name,
        profile_selection.definition().id.as_str(),
        profile_selection.modules(),
        profile_selection.providers(),
        profile_selection.runtime_dependencies(),
        request.release_identity,
    )?;
    let file_count = rendered.len() + 1;
    let state_index = rendered
        .iter()
        .position(|file| file.path == PROJECT_STATE_PATH)
        .ok_or_else(|| RenderError::Canonical("rendered project state is missing".to_owned()))?;
    let state_file = rendered.remove(state_index);
    for file in &rendered {
        write_project_file(staging_area.path(), &file.path, file.contents.as_bytes())
            .map_err(RenderError::Lifecycle)?;
    }
    let provenance = inspect_project_provenance(
        staging_area.path(),
        request.release_identity,
        profile_selection.modules(),
    )
    .map_err(|error| RenderError::Provenance(error.to_string()))?;
    if !provenance.findings.is_empty() {
        let diagnostics = provenance
            .findings
            .iter()
            .map(|finding| format!("{} at {}: {}", finding.code, finding.path, finding.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(RenderError::Provenance(diagnostics));
    }
    let candidate = lockfile_resolver
        .resolve(&CargoResolverRequest::new_project(
            staging_area.path(),
            request.release_identity.clone(),
            offline,
        ))
        .map_err(RenderError::Resolver)?;
    write_project_file(staging_area.path(), "Cargo.lock", candidate.lockfile())
        .map_err(RenderError::Lifecycle)?;
    write_project_file(
        staging_area.path(),
        PROJECT_STATE_PATH,
        state_file.contents.as_bytes(),
    )
    .map_err(RenderError::Lifecycle)?;
    staging_area
        .publish(request.destination)
        .map_err(|error| match error {
            LifecycleError::DestinationExists(path) => RenderError::DestinationExists(path),
            other => RenderError::Lifecycle(other),
        })?;
    Ok(RenderOutcome { files: file_count })
}

#[derive(Debug)]
struct RenderedFile {
    path: String,
    contents: String,
    ownership: Ownership,
}

fn render_files(
    service_name: &str,
    profile: &str,
    modules: &[String],
    providers: &[crate::ProviderSelection],
    runtime_dependencies: &[crate::RuntimeDependencyId],
    release_identity: &ReleaseIdentity,
) -> Result<Vec<RenderedFile>, RenderError> {
    let catalog = crate::ModuleCatalog::bundled()
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
    validate_application_template_catalog(&catalog).map_err(RenderError::Canonical)?;
    if catalog.bundle_version != release_identity.version() {
        return Err(RenderError::Canonical(format!(
            "release version `{}` does not match bundled catalog version `{}`",
            release_identity.version(),
            catalog.bundle_version
        )));
    }

    let mut rendered = render_base_files(
        service_name,
        profile,
        modules,
        providers,
        runtime_dependencies,
        release_identity,
        &catalog,
    )?;
    let base_files = rendered
        .iter()
        .map(|file| (file.path.clone(), file.contents.clone()))
        .collect::<BTreeMap<_, _>>();
    for module_id in modules {
        let module = catalog.module(module_id).ok_or_else(|| {
            RenderError::Canonical(format!(
                "profile selects unknown application-template module `{module_id}`"
            ))
        })?;
        for path in &module.application_templates {
            let descriptor = application_template(module_id, path).ok_or_else(|| {
                RenderError::Canonical(format!(
                    "application template `{path}` for module `{module_id}` is not embedded"
                ))
            })?;
            rendered.push(RenderedFile {
                path: path.clone(),
                contents: descriptor.source.to_owned(),
                ownership: Ownership::Application,
            });
        }
    }
    canonicalize_profile(
        &mut rendered,
        modules,
        &catalog,
        release_identity,
        base_files,
    )?;
    Ok(rendered)
}

fn render_base_files(
    service_name: &str,
    profile: &str,
    modules: &[String],
    providers: &[crate::ProviderSelection],
    runtime_dependencies: &[crate::RuntimeDependencyId],
    release_identity: &ReleaseIdentity,
    catalog: &crate::ModuleCatalog,
) -> Result<Vec<RenderedFile>, RenderError> {
    let mut rendered = Vec::with_capacity(TEMPLATE_FILES.len() + 1);
    let web_static = modules.iter().any(|module| module == "web-static");
    for file in TEMPLATE_FILES {
        let source = file.source.replace("{{project-name}}", service_name);
        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment.set_auto_escape_callback(|_| AutoEscape::None);
        environment.set_keep_trailing_newline(true);
        environment
            .add_template_owned(file.path, source)
            .map_err(RenderError::Template)?;
        let template = environment
            .get_template(file.path)
            .map_err(RenderError::Template)?;
        let contents = template
            .render(context! {
                profile => profile,
                kit_version => release_identity.version(),
                resolved_context => true,
                web_static => web_static,
                modules => modules,
                providers => providers,
                runtime_dependencies => runtime_dependencies,
            })
            .map_err(RenderError::Template)?;
        rendered.push(RenderedFile {
            path: file.path.to_owned(),
            contents,
            ownership: file.ownership,
        });
    }
    let state = initial_project_state(
        service_name,
        profile,
        modules,
        providers,
        release_identity,
        catalog,
    )?;
    rendered.push(RenderedFile {
        path: PROJECT_STATE_PATH.to_owned(),
        contents: state
            .to_toml()
            .map_err(|error| RenderError::Canonical(error.to_string()))?,
        ownership: Ownership::Kit,
    });
    Ok(rendered)
}

fn initial_project_state(
    service_name: &str,
    profile: &str,
    modules: &[String],
    providers: &[crate::ProviderSelection],
    release_identity: &ReleaseIdentity,
    catalog: &crate::ModuleCatalog,
) -> Result<ProjectState, RenderError> {
    let modules = modules
        .iter()
        .map(|id| {
            let definition = catalog.module(id).ok_or_else(|| {
                RenderError::Canonical(format!("profile selects unknown module `{id}`"))
            })?;
            Ok(SelectedModule {
                id: id.clone(),
                version: definition.version.clone(),
            })
        })
        .collect::<Result<Vec<_>, RenderError>>()?;
    let providers = providers
        .iter()
        .map(|provider| SelectedProvider {
            slot: provider.slot.clone(),
            module: provider.module.clone(),
        })
        .collect();
    let empty_hash = sha256_hex(b"");
    Ok(ProjectState {
        schema_version: PROJECT_STATE_SCHEMA_VERSION,
        service: service_name.to_owned(),
        framework: release_identity.clone(),
        profile: ProfileSelection {
            id: profile.to_owned(),
            version: catalog.bundle_version.clone(),
            additions: Vec::new(),
            removals: Vec::new(),
        },
        modules,
        providers,
        retained_compose_volumes: Vec::new(),
        ownership: vec![OwnershipRecord {
            path: "Cargo.lock".to_owned(),
            kind: OwnershipKind::DependencyLock,
            approved_sha256: None,
        }],
        managed_regions: vec![
            ManagedRegionRecord {
                id: "framework-dependency".to_owned(),
                path: "Cargo.toml".to_owned(),
                marker_version: MANAGED_MARKER_VERSION,
                content_hash: empty_hash.clone(),
            },
            ManagedRegionRecord {
                id: "modules".to_owned(),
                path: "apps/service/src/composition.rs".to_owned(),
                marker_version: MANAGED_MARKER_VERSION,
                content_hash: empty_hash,
            },
        ],
    })
}

fn canonicalize_profile(
    rendered: &mut Vec<RenderedFile>,
    modules: &[String],
    catalog: &crate::ModuleCatalog,
    release_identity: &ReleaseIdentity,
    base_files: BTreeMap<String, String>,
) -> Result<(), RenderError> {
    let selected = modules.iter().cloned().collect::<BTreeSet<_>>();
    let state_index = rendered
        .iter()
        .position(|file| file.path == PROJECT_STATE_PATH)
        .ok_or_else(|| RenderError::Canonical("rendered state is missing".to_owned()))?;
    let mut initial_state = ProjectState::parse(&rendered[state_index].contents)
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
    retain_selected_compose_volumes(&mut initial_state, catalog)
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
    append_derived_files(rendered, catalog, &selected, &initial_state)?;
    record_rendered_ownership(rendered, &mut initial_state)?;
    normalize_next_state(&mut initial_state, release_identity);
    rendered[state_index].contents = initial_state
        .to_toml()
        .map_err(|error| RenderError::Canonical(error.to_string()))?;

    let files = rendered
        .iter()
        .map(|file| (file.path.clone(), file.contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let (mut composed_state, mut composed_files) =
        compose_initial_profile(catalog, release_identity, initial_state, files, base_files)
            .map_err(|error| RenderError::Canonical(error.to_string()))?;
    refresh_approved_hashes(&mut composed_state, &composed_files)?;
    normalize_next_state(&mut composed_state, release_identity);
    composed_files.insert(
        PROJECT_STATE_PATH.to_owned(),
        composed_state
            .to_toml()
            .map_err(|error| RenderError::Canonical(error.to_string()))?,
    );
    merge_composed_files(rendered, &composed_state, composed_files)
}

fn append_derived_files(
    rendered: &mut Vec<RenderedFile>,
    catalog: &crate::ModuleCatalog,
    selected: &BTreeSet<String>,
    state: &ProjectState,
) -> Result<(), RenderError> {
    for &path in MANAGER_DERIVED_PATHS {
        let contents = render_derived_with_retained_volumes(
            path,
            catalog,
            selected,
            &state.service,
            &state.retained_compose_volumes,
        )
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
        rendered.push(RenderedFile {
            path: path.to_owned(),
            contents,
            ownership: Ownership::Derived,
        });
    }
    Ok(())
}

fn record_rendered_ownership(
    rendered: &[RenderedFile],
    state: &mut ProjectState,
) -> Result<(), RenderError> {
    for file in rendered {
        if file.path == PROJECT_STATE_PATH {
            continue;
        }
        let kind = match file.ownership {
            Ownership::Kit => OwnershipKind::KitOwned,
            Ownership::Application => OwnershipKind::ApplicationOwned,
            Ownership::Derived => OwnershipKind::Derived,
        };
        let approved_sha256 = match kind {
            OwnershipKind::KitOwned | OwnershipKind::Derived => {
                Some(sha256_hex(file.contents.as_bytes()))
            }
            OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock => None,
        };
        match state
            .ownership
            .iter_mut()
            .find(|record| record.path == file.path)
        {
            Some(existing) if existing.kind != kind => {
                return Err(RenderError::Canonical(format!(
                    "template ownership for `{}` is `{:?}`, expected `{kind:?}`",
                    file.path, existing.kind
                )));
            }
            Some(existing) => existing.approved_sha256 = approved_sha256,
            None => state.ownership.push(OwnershipRecord {
                path: file.path.clone(),
                kind,
                approved_sha256,
            }),
        }
    }
    Ok(())
}

fn merge_composed_files(
    rendered: &mut Vec<RenderedFile>,
    state: &ProjectState,
    mut composed: BTreeMap<String, String>,
) -> Result<(), RenderError> {
    for file in rendered.iter_mut() {
        file.contents = composed.remove(&file.path).ok_or_else(|| {
            RenderError::Canonical(format!(
                "initial composition removed rendered file `{}`",
                file.path
            ))
        })?;
    }
    for (path, contents) in composed {
        let ownership = match state.ownership_of(&path) {
            Some(OwnershipKind::KitOwned) => Ownership::Kit,
            Some(OwnershipKind::Derived) => Ownership::Derived,
            Some(OwnershipKind::ApplicationOwned) => Ownership::Application,
            Some(OwnershipKind::DependencyLock) => {
                return Err(RenderError::Canonical(format!(
                    "initial composition unexpectedly produced dependency lock `{path}`"
                )));
            }
            None => {
                return Err(RenderError::Canonical(format!(
                    "initial composition produced unowned file `{path}`"
                )));
            }
        };
        rendered.push(RenderedFile {
            path,
            contents,
            ownership,
        });
    }
    rendered.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(())
}

fn refresh_approved_hashes(
    state: &mut ProjectState,
    files: &BTreeMap<String, String>,
) -> Result<(), RenderError> {
    for record in &mut state.ownership {
        if record.path == PROJECT_STATE_PATH {
            return Err(RenderError::Canonical(
                "rendered state must not own itself".to_owned(),
            ));
        }
        record.approved_sha256 = match record.kind {
            OwnershipKind::KitOwned | OwnershipKind::Derived => {
                let contents = files.get(&record.path).ok_or_else(|| {
                    RenderError::Canonical(format!(
                        "rendered ownership references missing file `{}`",
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
pub(crate) fn render_managed_dockerfile(
    service_name: &str,
    selected: &BTreeSet<String>,
) -> Result<String, RenderError> {
    let source = include_str!("../../../templates/base-service/ops/Dockerfile")
        .replace("{{project-name}}", service_name);
    let mut environment = Environment::new();
    environment.set_undefined_behavior(UndefinedBehavior::Strict);
    environment.set_auto_escape_callback(|_| AutoEscape::None);
    environment.set_keep_trailing_newline(true);
    environment
        .add_template_owned("ops/Dockerfile", source)
        .map_err(RenderError::Template)?;
    environment
        .get_template("ops/Dockerfile")
        .map_err(RenderError::Template)?
        .render(context! {
            profile => "",
            web_static => selected.contains("web-static"),
        })
        .map_err(RenderError::Template)
}

pub(crate) fn render_embedded_base_files(
    service_name: &str,
    profile: &str,
    release_identity: &ReleaseIdentity,
) -> Result<BTreeMap<String, String>, RenderError> {
    validate_service_name(service_name)?;
    let resolved = resolve_profile(profile)?;
    let catalog = crate::ModuleCatalog::bundled()
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
    Ok(render_base_files(
        service_name,
        resolved.definition().id.as_str(),
        resolved.modules(),
        resolved.providers(),
        resolved.runtime_dependencies(),
        release_identity,
        &catalog,
    )?
    .into_iter()
    .map(|file| (file.path, file.contents))
    .collect())
}

fn validate_service_name(name: &str) -> Result<(), RenderError> {
    let bytes = name.as_bytes();
    let valid = name.len() <= 64
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(RenderError::InvalidServiceName)
    }
}
