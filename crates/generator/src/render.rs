use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use minijinja::{AutoEscape, Environment, UndefinedBehavior, context};

use crate::{
    KIT_VERSION, PROJECT_STATE_PATH, ProfileError,
    manager::{
        MANAGER_DERIVED_PATHS, compose_initial_profile, normalize_next_state, render_derived,
        render_modules_region,
    },
    resolve_profile,
    state::{OwnershipKind, OwnershipRecord, ProjectState, sha256_hex},
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
        ".config/nextest.toml",
        "../../../templates/base-service/.config/nextest.toml",
        Kit
    ),
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
        ".omnius/service.toml",
        "../../../templates/base-service/.omnius/service.toml",
        Kit
    ),
    template!(
        "Cargo.toml",
        "../../../templates/base-service/Cargo.toml",
        Kit
    ),
    template!(
        "README.md",
        "../../../templates/base-service/README.md",
        Application
    ),
    template!(
        "apps/service/Cargo.toml",
        "../../../templates/base-service/apps/service/Cargo.toml",
        Kit
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
        Kit
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
        "crates/service-kit/Cargo.toml",
        "../../../templates/base-service/crates/service-kit/Cargo.toml",
        Kit
    ),
    template!(
        "crates/service-kit/src/lib.rs",
        "../../../templates/base-service/crates/service-kit/src/lib.rs",
        Kit
    ),
    template!(
        "docs/operations.md",
        "../../../templates/base-service/docs/operations.md",
        Kit
    ),
    template!(
        "ops/Dockerfile",
        "../../../templates/base-service/ops/Dockerfile",
        Kit
    ),
    template!(
        "ops/compose.yaml",
        "../../../templates/base-service/ops/compose.yaml",
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
    /// One of the nine authoritative base profile identifiers.
    pub profile: &'a str,
    /// Empty destination on first expansion.
    pub destination: &'a Path,
}

/// Result of a safe expansion pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderOutcome {
    /// A new project tree was written.
    Created {
        /// Number of template files written.
        files: usize,
    },
    /// The existing generated files already matched byte-for-byte.
    Unchanged {
        /// Number of expected template files verified.
        files: usize,
    },
}

/// Failure to validate or safely expand a base service.
#[derive(Debug)]
pub enum RenderError {
    /// The requested service name was not canonical Cargo kebab case.
    InvalidServiceName,
    /// The selected base profile was invalid or unknown.
    Profile(ProfileError),
    /// The destination contained files without generator state.
    DestinationNotEmpty,
    /// A kit-owned output differed or was missing, so it was not overwritten.
    GeneratedFileConflict(PathBuf),
    /// A bundled template could not be evaluated.
    Template(minijinja::Error),
    /// Canonical manager-owned state or artifact generation failed.
    Canonical(String),
    /// A filesystem operation failed.
    Filesystem(io::Error),
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceName => formatter.write_str(
                "service name must start with a lowercase ASCII letter and contain only lowercase ASCII letters, digits, and internal hyphens",
            ),
            Self::Profile(error) => write!(formatter, "cannot resolve service profile: {error}"),
            Self::DestinationNotEmpty => formatter.write_str(
                "generation destination is not empty and has no matching .omnius/service.toml",
            ),
            Self::GeneratedFileConflict(path) => write!(
                formatter,
                "refusing to overwrite changed or missing kit-owned file: {}",
                path.display()
            ),
            Self::Canonical(message) => {
                write!(formatter, "cannot canonicalize generated profile: {message}")
            }
            Self::Template(error) => write!(formatter, "base service template failed: {error}"),
            Self::Filesystem(error) => write!(formatter, "base service filesystem operation failed: {error}"),
        }
    }
}

impl Error for RenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Profile(error) => Some(error),
            Self::Template(error) => Some(error),
            Self::Filesystem(error) => Some(error),
            Self::InvalidServiceName
            | Self::DestinationNotEmpty
            | Self::GeneratedFileConflict(_)
            | Self::Canonical(_) => None,
        }
    }
}

impl From<ProfileError> for RenderError {
    fn from(error: ProfileError) -> Self {
        Self::Profile(error)
    }
}

/// Expands the cargo-generate base template without invoking a child command.
///
/// A first pass requires an empty destination. Later identical passes compare
/// kit-owned files and leave application-owned files and unknown extra files
/// untouched. Any changed kit-owned output causes an error rather than an
/// overwrite.
///
/// # Errors
///
/// Returns [`RenderError`] for invalid inputs, an unsafe destination, a
/// template evaluation failure, or a filesystem failure.
pub fn render_project(request: RenderRequest<'_>) -> Result<RenderOutcome, RenderError> {
    validate_service_name(request.service_name)?;
    let resolved = resolve_profile(request.profile)?;
    fs::create_dir_all(request.destination).map_err(RenderError::Filesystem)?;
    let empty = directory_is_empty(request.destination)?;
    if !empty && !request.destination.join(PROJECT_STATE_PATH).is_file() {
        return Err(RenderError::DestinationNotEmpty);
    }
    let rendered = render_files(
        request.service_name,
        resolved.definition().id.as_str(),
        resolved.modules(),
        resolved.providers(),
        resolved.external_services(),
    )?;
    if !empty {
        verify_existing(request.destination, &rendered)?;
        return Ok(RenderOutcome::Unchanged {
            files: rendered.len(),
        });
    }

    for file in &rendered {
        let destination = request.destination.join(&file.path);
        let parent = destination
            .parent()
            .ok_or_else(|| RenderError::GeneratedFileConflict(PathBuf::from(file.path.clone())))?;
        fs::create_dir_all(parent).map_err(RenderError::Filesystem)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    RenderError::GeneratedFileConflict(PathBuf::from(file.path.clone()))
                } else {
                    RenderError::Filesystem(error)
                }
            })?;
        output
            .write_all(file.contents.as_bytes())
            .map_err(RenderError::Filesystem)?;
    }
    Ok(RenderOutcome::Created {
        files: rendered.len(),
    })
}

#[derive(Debug)]
struct RenderedFile {
    path: String,
    contents: String,
    ownership: Ownership,
    raw_cargo_template: Option<String>,
}

fn render_files(
    service_name: &str,
    profile: &str,
    modules: &[String],
    providers: &[crate::ProviderSelection],
    external_services: &[String],
) -> Result<Vec<RenderedFile>, RenderError> {
    let mut rendered = Vec::with_capacity(TEMPLATE_FILES.len());
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
                kit_version => KIT_VERSION,
                resolved_context => true,
                modules => modules,
                providers => providers,
                external_services => external_services,
            })
            .map_err(RenderError::Template)?;
        let raw_cargo_template = (file.path == "Cargo.toml").then(|| contents.clone());
        rendered.push(RenderedFile {
            path: file.path.to_owned(),
            contents,
            ownership: file.ownership,
            raw_cargo_template,
        });
    }
    canonicalize_profile(&mut rendered, modules)?;
    Ok(rendered)
}

fn canonicalize_profile(
    rendered: &mut Vec<RenderedFile>,
    modules: &[String],
) -> Result<(), RenderError> {
    let selected = modules.iter().cloned().collect::<BTreeSet<_>>();
    let catalog = crate::ModuleCatalog::bundled()
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
    let state_index = rendered
        .iter()
        .position(|file| file.path == PROJECT_STATE_PATH)
        .ok_or_else(|| RenderError::Canonical("rendered state is missing".to_owned()))?;
    let composition_index = rendered
        .iter()
        .position(|file| file.path == "apps/service/src/composition.rs")
        .ok_or_else(|| RenderError::Canonical("rendered composition is missing".to_owned()))?;
    let mut state = ProjectState::parse(&rendered[state_index].contents)
        .map_err(|error| RenderError::Canonical(error.to_string()))?;
    let record = state
        .managed_regions
        .iter()
        .find(|record| record.path == "apps/service/src/composition.rs" && record.id == "modules")
        .cloned()
        .ok_or_else(|| RenderError::Canonical("module region state is missing".to_owned()))?;
    let desired_region = render_modules_region(&selected);
    rendered[composition_index].contents = crate::reconcile_managed_region(
        &rendered[composition_index].contents,
        &record,
        &desired_region,
    )
    .map_err(|error| RenderError::Canonical(error.to_string()))?;
    let state_record = state
        .managed_regions
        .iter_mut()
        .find(|record| record.path == "apps/service/src/composition.rs" && record.id == "modules")
        .ok_or_else(|| RenderError::Canonical("module region state disappeared".to_owned()))?;
    state_record.content_hash = sha256_hex(desired_region.as_bytes());
    for &path in MANAGER_DERIVED_PATHS {
        let contents = render_derived(path, &catalog, &selected)
            .map_err(|error| RenderError::Canonical(error.to_string()))?;
        state.ownership.push(OwnershipRecord {
            path: path.to_owned(),
            kind: OwnershipKind::Derived,
        });
        rendered.push(RenderedFile {
            path: path.to_owned(),
            contents,
            ownership: Ownership::Derived,
            raw_cargo_template: None,
        });
    }
    normalize_next_state(&mut state, &catalog.bundle_version);
    rendered[state_index].contents = state
        .to_toml()
        .map_err(|error| RenderError::Canonical(error.to_string()))?;

    let files = rendered
        .iter()
        .map(|file| (file.path.clone(), file.contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let kit_sources = rendered
        .iter()
        .filter(|file| file.ownership == Ownership::Kit)
        .map(|file| (file.path.clone(), file.contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let kit_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (state, mut composed) =
        compose_initial_profile(&kit_root, &catalog, state, files, kit_sources)
            .map_err(|error| RenderError::Canonical(error.to_string()))?;
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
            raw_cargo_template: None,
        });
    }
    rendered.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(())
}

pub(crate) fn render_kit_baselines(
    service_name: &str,
    profile: &str,
) -> Result<BTreeMap<String, String>, RenderError> {
    validate_service_name(service_name)?;
    let resolved = resolve_profile(profile)?;
    let rendered = render_files(
        service_name,
        resolved.definition().id.as_str(),
        resolved.modules(),
        resolved.providers(),
        resolved.external_services(),
    )?;
    Ok(rendered
        .into_iter()
        .filter(|file| file.ownership == Ownership::Kit)
        .map(|file| {
            let contents = if file.path == "Cargo.toml" {
                file.raw_cargo_template.unwrap_or(file.contents)
            } else {
                file.contents
            };
            (file.path, contents)
        })
        .collect())
}

fn verify_existing(root: &Path, rendered: &[RenderedFile]) -> Result<(), RenderError> {
    for file in rendered {
        if file.ownership == Ownership::Application {
            continue;
        }
        let path = root.join(&file.path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| RenderError::GeneratedFileConflict(PathBuf::from(file.path.clone())))?;
        if !metadata.is_file() {
            return Err(RenderError::GeneratedFileConflict(PathBuf::from(
                file.path.clone(),
            )));
        }
        let contents = fs::read(&path).map_err(RenderError::Filesystem)?;
        if contents != file.contents.as_bytes() {
            return Err(RenderError::GeneratedFileConflict(PathBuf::from(
                file.path.clone(),
            )));
        }
    }
    Ok(())
}

fn directory_is_empty(path: &Path) -> Result<bool, RenderError> {
    fs::read_dir(path)
        .map_err(RenderError::Filesystem)?
        .next()
        .transpose()
        .map(|entry| entry.is_none())
        .map_err(RenderError::Filesystem)
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
