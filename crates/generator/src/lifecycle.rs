//! Sibling staging and sealed-input verification for service lifecycle operations.

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fs::{CWD, RenameFlags, renameat_with};
use rustix::io::Errno;

use crate::state::{sha256_hex, validate_relative_path};

const OMITTED_ROOT_DIRECTORIES: &[&str] = &[".git", "target"];
const OMITTED_CONTROL_FILES: &[&str] = &[
    ".omnius/lifecycle.lock",
    ".omnius/transaction.json",
    ".omnius/.transaction.json.tmp",
    ".omnius/.transaction.json.tmp.ready",
];
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Failure while staging, publishing, or verifying a lifecycle project tree.
#[derive(Debug)]
pub enum LifecycleError {
    /// A new-project destination already exists.
    DestinationExists(PathBuf),
    /// A project tree contains an unsafe or unsupported entry.
    InvalidProject(String),
    /// A filesystem operation failed.
    Filesystem {
        /// Operation being performed.
        operation: &'static str,
        /// Path involved in the failure.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationExists(path) => {
                write!(
                    formatter,
                    "new-project destination already exists: {}",
                    path.display()
                )
            }
            Self::InvalidProject(message) => formatter.write_str(message),
            Self::Filesystem {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "cannot {operation} `{}`: {source}",
                path.display()
            ),
        }
    }
}

impl Error for LifecycleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Filesystem { source, .. } => Some(source),
            Self::DestinationExists(_) | Self::InvalidProject(_) => None,
        }
    }
}

/// Distinct byte-copied sibling trees used for one existing-project resolution.
pub(crate) struct ExistingProjectStages {
    current: OwnedSiblingStage,
    candidate: OwnedSiblingStage,
    expected_inputs: BTreeMap<String, String>,
}

impl ExistingProjectStages {
    pub(crate) fn create(project_root: &Path) -> Result<Self, LifecycleError> {
        let project_root = canonical_existing_project_root(project_root)?;
        let current = OwnedSiblingStage::create(&project_root, "current")?;
        let candidate = OwnedSiblingStage::create(&project_root, "candidate")?;
        let expected_inputs = copy_project_tree(&project_root, current.path())?;
        let candidate_inputs = copy_project_tree(&project_root, candidate.path())?;
        if candidate_inputs != expected_inputs {
            return Err(LifecycleError::InvalidProject(
                "project bytes changed while lifecycle staging was in progress".to_owned(),
            ));
        }
        Ok(Self {
            current,
            candidate,
            expected_inputs,
        })
    }

    pub(crate) fn current(&self) -> &Path {
        self.current.path()
    }

    pub(crate) fn candidate(&self) -> &Path {
        self.candidate.path()
    }

    pub(crate) fn expected_inputs(&self) -> &BTreeMap<String, String> {
        &self.expected_inputs
    }
}

/// An owned sibling directory removed automatically unless atomically published.
pub(crate) struct OwnedSiblingStage {
    path: PathBuf,
    active: bool,
}

impl OwnedSiblingStage {
    pub(crate) fn create_for_new(destination: &Path) -> Result<Self, LifecycleError> {
        match fs::symlink_metadata(destination) {
            Ok(_) => return Err(LifecycleError::DestinationExists(destination.to_path_buf())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(filesystem(
                    "inspect new-project destination",
                    destination,
                    source,
                ));
            }
        }
        Self::create(destination, "new")
    }

    fn create(destination: &Path, label: &str) -> Result<Self, LifecycleError> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure_real_directory(parent, "inspect destination parent")?;
        let name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                LifecycleError::InvalidProject(format!(
                    "lifecycle destination has an invalid name: {}",
                    destination.display()
                ))
            })?;
        for _ in 0..128 {
            let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".{name}.omnius-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, active: true }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(filesystem("create sibling stage", path, source));
                }
            }
        }
        Err(LifecycleError::InvalidProject(format!(
            "could not allocate a unique sibling stage for {}",
            destination.display()
        )))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn publish(mut self, destination: &Path) -> Result<(), LifecycleError> {
        match renameat_with(CWD, &self.path, CWD, destination, RenameFlags::NOREPLACE) {
            Ok(()) => self.active = false,
            Err(error) if error == Errno::EXIST || error == Errno::NOTEMPTY => {
                return Err(LifecycleError::DestinationExists(destination.to_path_buf()));
            }
            Err(error) => {
                return Err(filesystem(
                    "publish sibling stage",
                    destination,
                    io::Error::from_raw_os_error(error.raw_os_error()),
                ));
            }
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| filesystem("sync destination parent", parent, source))
    }
}

impl Drop for OwnedSiblingStage {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn write_project_file(
    root: &Path,
    relative: &str,
    contents: &[u8],
) -> Result<(), LifecycleError> {
    validate_relative_path(relative)
        .map_err(|error| LifecycleError::InvalidProject(error.to_string()))?;
    ensure_safe_relative_target(root, relative)?;
    let path = root.join(relative);
    let parent = path.parent().ok_or_else(|| {
        LifecycleError::InvalidProject(format!("project path has no parent: `{relative}`"))
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| filesystem("create staged parent directory", parent, source))?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(LifecycleError::InvalidProject(format!(
                "staged project path is not a regular file: `{relative}`"
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(filesystem("inspect staged file", path, source)),
    }
    fs::write(&path, contents).map_err(|source| filesystem("write staged file", path, source))
}

pub(crate) fn remove_project_file(root: &Path, relative: &str) -> Result<(), LifecycleError> {
    validate_relative_path(relative)
        .map_err(|error| LifecycleError::InvalidProject(error.to_string()))?;
    ensure_safe_relative_target(root, relative)?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| filesystem("inspect staged file", &path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LifecycleError::InvalidProject(format!(
            "staged project path is not a regular file: `{relative}`"
        )));
    }
    fs::remove_file(&path).map_err(|source| filesystem("remove staged file", path, source))
}

pub(crate) fn read_regular_bytes(path: &Path) -> Result<Option<Vec<u8>>, LifecycleError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(filesystem("inspect project file", path, source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LifecycleError::InvalidProject(format!(
            "project path is not a regular file: {}",
            path.display()
        )));
    }
    fs::read(path)
        .map(Some)
        .map_err(|source| filesystem("read project file", path, source))
}

pub(crate) fn verify_project_inputs(
    project_root: &Path,
    expected: &BTreeMap<String, String>,
) -> Result<(), LifecycleError> {
    let actual = collect_project_hashes(project_root)?;
    if actual == *expected {
        return Ok(());
    }
    let changed = expected
        .keys()
        .chain(actual.keys())
        .find(|path| expected.get(*path) != actual.get(*path))
        .map_or("project tree", String::as_str);
    Err(LifecycleError::InvalidProject(format!(
        "sealed lifecycle input `{changed}` changed before apply"
    )))
}

fn copy_project_tree(
    source: &Path,
    destination: &Path,
) -> Result<BTreeMap<String, String>, LifecycleError> {
    let mut hashes = BTreeMap::new();
    copy_directory(source, destination, "", &mut hashes)?;
    Ok(hashes)
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    relative_parent: &str,
    hashes: &mut BTreeMap<String, String>,
) -> Result<(), LifecycleError> {
    let mut entries = fs::read_dir(source)
        .map_err(|source_error| filesystem("read project directory", source, source_error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source_error| filesystem("read project directory entry", source, source_error))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name: OsString = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            LifecycleError::InvalidProject(format!(
                "project contains a non-UTF-8 path below {}",
                source.display()
            ))
        })?;
        let relative = if relative_parent.is_empty() {
            name.to_owned()
        } else {
            format!("{relative_parent}/{name}")
        };
        if omitted_path(&relative) {
            continue;
        }
        let source_path = entry.path();
        let metadata = fs::symlink_metadata(&source_path).map_err(|source_error| {
            filesystem("inspect project entry", &source_path, source_error)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(LifecycleError::InvalidProject(format!(
                "project staging refuses symlink `{relative}`"
            )));
        }
        let destination_path = destination.join(&relative);
        if metadata.is_dir() {
            fs::create_dir(&destination_path).map_err(|source_error| {
                filesystem("create staged directory", &destination_path, source_error)
            })?;
            copy_directory(&source_path, destination, &relative, hashes)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&source_path).map_err(|source_error| {
                filesystem("read project file", &source_path, source_error)
            })?;
            fs::write(&destination_path, &bytes).map_err(|source_error| {
                filesystem("copy project file", &destination_path, source_error)
            })?;
            hashes.insert(relative, sha256_hex(&bytes));
        } else {
            return Err(LifecycleError::InvalidProject(format!(
                "project staging refuses non-regular entry `{relative}`"
            )));
        }
    }
    Ok(())
}

fn collect_project_hashes(root: &Path) -> Result<BTreeMap<String, String>, LifecycleError> {
    ensure_real_directory(root, "inspect project root")?;
    let mut hashes = BTreeMap::new();
    collect_directory_hashes(root, "", &mut hashes)?;
    Ok(hashes)
}

fn collect_directory_hashes(
    directory: &Path,
    relative_parent: &str,
    hashes: &mut BTreeMap<String, String>,
) -> Result<(), LifecycleError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| filesystem("read project directory", directory, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| filesystem("read project directory entry", directory, source))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            LifecycleError::InvalidProject(format!(
                "project contains a non-UTF-8 path below {}",
                directory.display()
            ))
        })?;
        let relative = if relative_parent.is_empty() {
            name.to_owned()
        } else {
            format!("{relative_parent}/{name}")
        };
        if omitted_path(&relative) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| filesystem("inspect project entry", &path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(LifecycleError::InvalidProject(format!(
                "project staging refuses symlink `{relative}`"
            )));
        }
        if metadata.is_dir() {
            collect_directory_hashes(&path, &relative, hashes)?;
        } else if metadata.is_file() {
            let bytes =
                fs::read(&path).map_err(|source| filesystem("read project file", &path, source))?;
            hashes.insert(relative, sha256_hex(&bytes));
        } else {
            return Err(LifecycleError::InvalidProject(format!(
                "project staging refuses non-regular entry `{relative}`"
            )));
        }
    }
    Ok(())
}

fn omitted_path(relative: &str) -> bool {
    let first = relative.split('/').next().unwrap_or_default();
    OMITTED_ROOT_DIRECTORIES.contains(&first) || OMITTED_CONTROL_FILES.contains(&relative)
}

fn ensure_safe_relative_target(root: &Path, relative: &str) -> Result<(), LifecycleError> {
    ensure_real_directory(root, "inspect staged project")?;
    let components = relative.split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(LifecycleError::InvalidProject(format!(
                    "staged project path has a symlinked component: `{relative}`"
                )));
            }
            Ok(metadata) if index + 1 < components.len() && !metadata.is_dir() => {
                return Err(LifecycleError::InvalidProject(format!(
                    "staged project path has a non-directory ancestor: `{relative}`"
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(source) => return Err(filesystem("inspect staged project path", current, source)),
        }
    }
    Ok(())
}

fn canonical_existing_project_root(project_root: &Path) -> Result<PathBuf, LifecycleError> {
    ensure_real_directory(project_root, "inspect project root")?;
    fs::canonicalize(project_root)
        .map_err(|source| filesystem("resolve project root", project_root, source))
}

fn ensure_real_directory(path: &Path, operation: &'static str) -> Result<(), LifecycleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| filesystem(operation, path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LifecycleError::InvalidProject(format!(
            "project directory must be a real directory, not a symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

fn filesystem(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: io::Error,
) -> LifecycleError {
    LifecycleError::Filesystem {
        operation,
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_directory_is_a_valid_existing_project_root() -> Result<(), LifecycleError> {
        let root = canonical_existing_project_root(Path::new("."))?;

        assert!(root.is_absolute());
        assert!(root.file_name().is_some());
        Ok(())
    }
}
