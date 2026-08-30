use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// Default relative directory used by official and synthetic evidence.
pub const DEFAULT_ARTIFACT_DIRECTORY: &str = "artifacts/mcp-conformance";

/// A UTF-8 relative path with no traversal, root, or platform prefix components.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeRelativePath(String);

impl SafeRelativePath {
    /// Parses a path that is safe to resolve beneath a separately trusted directory.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::UnsafeRelativePath`] when the path is non-UTF-8, empty, absolute,
    /// contains traversal or platform-prefix components, or contains disallowed separators.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        let path = path.as_ref();
        let Some(path_string) = path.to_str() else {
            return Err(ArtifactError::UnsafeRelativePath);
        };
        if path_string.is_empty()
            || path_string
                .chars()
                .any(|character| matches!(character, '\\' | ':'))
            || path_string
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ArtifactError::UnsafeRelativePath);
        }
        Ok(Self(path_string.to_owned()))
    }

    /// Returns the validated relative path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Returns the path as a command-line-safe UTF-8 argument.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Appends another validated relative path.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::UnsafeRelativePath`] if the combined path violates the safe
    /// relative-path invariant.
    pub fn join(&self, child: &Self) -> Result<Self, ArtifactError> {
        Self::new(self.as_path().join(child.as_path()))
    }
}

impl Serialize for SafeRelativePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SafeRelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A symlink-rejecting evidence store rooted below a trusted workspace directory.
#[derive(Clone, Debug)]
pub struct ArtifactStore {
    workspace_root: PathBuf,
    artifact_directory: SafeRelativePath,
}

impl ArtifactStore {
    /// Creates and validates an artifact directory beneath `workspace_root`.
    ///
    /// # Errors
    ///
    /// Returns an error if the workspace root cannot be canonicalized or is not a directory, or
    /// if the artifact directory cannot be safely created without traversing a symlink.
    pub fn prepare(
        workspace_root: impl AsRef<Path>,
        artifact_directory: SafeRelativePath,
    ) -> Result<Self, ArtifactError> {
        let workspace_root = workspace_root
            .as_ref()
            .canonicalize()
            .map_err(ArtifactError::WorkspaceRoot)?;
        if !workspace_root.is_dir() {
            return Err(ArtifactError::WorkspaceRootNotDirectory);
        }
        ensure_directory_chain(&workspace_root, artifact_directory.as_path())?;
        Ok(Self {
            workspace_root,
            artifact_directory,
        })
    }

    /// Returns the validated artifact directory passed to an external tool.
    #[must_use]
    pub fn artifact_directory(&self) -> &SafeRelativePath {
        &self.artifact_directory
    }

    /// Writes an immutable JSON file at an arbitrary validated nested workspace-relative path.
    ///
    /// # Errors
    ///
    /// Returns an error if `relative_file` is not nested, the workspace or destination cannot be
    /// safely inspected or created, the file is not JSON, the content exceeds `max_bytes`, or the
    /// immutable write fails.
    pub fn write_workspace_json(
        workspace_root: impl AsRef<Path>,
        relative_file: &SafeRelativePath,
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<PathBuf, ArtifactError> {
        let parent = relative_file
            .as_path()
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or(ArtifactError::NestedJsonPathRequired)?;
        let file_name = relative_file
            .as_path()
            .file_name()
            .ok_or(ArtifactError::NestedJsonPathRequired)?;
        let store = Self::prepare(workspace_root, SafeRelativePath::new(parent)?)?;
        store.write_json(&SafeRelativePath::new(file_name)?, bytes, max_bytes)
    }

    /// Writes a nested immutable JSON file or accepts an identical existing regular file.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::write_workspace_json`], or when an
    /// existing destination is a symlink, is too large, is not a regular file, or differs from
    /// `bytes`.
    pub fn write_workspace_json_if_unchanged(
        workspace_root: impl AsRef<Path>,
        relative_file: &SafeRelativePath,
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<PathBuf, ArtifactError> {
        let workspace_root = workspace_root.as_ref();
        match Self::write_workspace_json(workspace_root, relative_file, bytes, max_bytes) {
            Ok(path) => Ok(path),
            Err(ArtifactError::Write(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                let root = workspace_root
                    .canonicalize()
                    .map_err(ArtifactError::WorkspaceRoot)?;
                let destination = root.join(relative_file.as_path());
                reject_symlink(&destination)?;
                let metadata = fs::metadata(&destination).map_err(ArtifactError::Inspect)?;
                let actual = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
                if !metadata.is_file() || actual > max_bytes {
                    return Err(ArtifactError::ExistingJsonMismatch);
                }
                let file = OpenOptions::new()
                    .read(true)
                    .open(&destination)
                    .map_err(ArtifactError::Inspect)?;
                let mut existing = Vec::with_capacity(actual);
                file.take(
                    u64::try_from(max_bytes)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut existing)
                .map_err(ArtifactError::Inspect)?;
                if existing != bytes {
                    return Err(ArtifactError::ExistingJsonMismatch);
                }
                Ok(destination)
            }
            Err(error) => Err(error),
        }
    }

    /// Writes an immutable JSON evidence file beneath the artifact directory.
    ///
    /// Existing files are never overwritten and symlink components are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the content exceeds `max_bytes`, the filename is not JSON, the
    /// destination cannot be safely created without symlink traversal, or writing it fails.
    pub fn write_json(
        &self,
        relative_file: &SafeRelativePath,
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<PathBuf, ArtifactError> {
        if bytes.len() > max_bytes {
            return Err(ArtifactError::EvidenceTooLarge {
                actual: bytes.len(),
                maximum: max_bytes,
            });
        }
        if relative_file
            .as_path()
            .extension()
            .and_then(|value| value.to_str())
            != Some("json")
        {
            return Err(ArtifactError::JsonExtensionRequired);
        }

        let combined = self.artifact_directory.join(relative_file)?;
        if let Some(parent) = combined.as_path().parent() {
            ensure_directory_chain(&self.workspace_root, parent)?;
        }
        let destination = self.workspace_root.join(combined.as_path());
        reject_symlink(&destination)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(ArtifactError::Write)?;
        file.write_all(bytes).map_err(ArtifactError::Write)?;
        file.sync_all().map_err(ArtifactError::Write)?;
        Ok(destination)
    }
}

fn ensure_directory_chain(root: &Path, relative: &Path) -> Result<(), ArtifactError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ArtifactError::UnsafeRelativePath);
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ArtifactError::SymlinkComponent(current));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ArtifactError::NonDirectoryComponent(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(ArtifactError::CreateDirectory)?;
                reject_symlink(&current)?;
            }
            Err(error) => return Err(ArtifactError::Inspect(error)),
        }
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), ArtifactError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ArtifactError::SymlinkComponent(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ArtifactError::Inspect(error)),
    }
}

/// Artifact path or persistence failure.
#[derive(Debug, Error)]
pub enum ArtifactError {
    /// A relative path was empty, non-UTF-8, absolute, or contained traversal.
    #[error("artifact paths must be non-empty normalized UTF-8 relative paths")]
    UnsafeRelativePath,
    /// The trusted workspace root could not be canonicalized.
    #[error("failed to resolve workspace root")]
    WorkspaceRoot(#[source] std::io::Error),
    /// The trusted workspace root was not a directory.
    #[error("workspace root is not a directory")]
    WorkspaceRootNotDirectory,
    /// A path component was a symlink.
    #[error("symlink components are forbidden in artifact paths: {0}")]
    SymlinkComponent(PathBuf),
    /// A path component existed but was not a directory.
    #[error("artifact directory component is not a directory: {0}")]
    NonDirectoryComponent(PathBuf),
    /// Metadata inspection failed.
    #[error("failed to inspect artifact path")]
    Inspect(#[source] std::io::Error),
    /// Artifact directory creation failed.
    #[error("failed to create artifact directory")]
    CreateDirectory(#[source] std::io::Error),
    /// Evidence writes failed, including an attempt to overwrite existing evidence.
    #[error("failed to write immutable evidence")]
    Write(#[source] std::io::Error),
    /// Evidence exceeded the configured byte bound.
    #[error("evidence was {actual} bytes, maximum is {maximum}")]
    EvidenceTooLarge {
        /// Actual serialized byte count.
        actual: usize,
        /// Maximum permitted byte count.
        maximum: usize,
    },
    /// Evidence files must use a JSON extension.
    #[error("evidence file must use the .json extension")]
    JsonExtensionRequired,
    /// Workspace-relative JSON writes require a directory component.
    #[error("workspace JSON path must include a validated parent directory")]
    NestedJsonPathRequired,
    /// An existing immutable JSON file differed from the generated content.
    #[error("existing workspace JSON differs from generated content")]
    ExistingJsonMismatch,
}
