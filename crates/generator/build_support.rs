#[path = "src/revision.rs"]
mod revision;

use std::{error::Error, fmt};

/// Git information observed for the source checkout at build time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSnapshot {
    /// The commit named by `HEAD^{commit}`.
    pub revision: String,
    /// Whether porcelain status reported any staged, unstaged, or untracked path.
    pub dirty: bool,
}

/// The release binding selected for this generator build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildBinding {
    /// No explicit revision and no source Git metadata were available.
    Unbound,
    /// The build is bound to an immutable revision.
    Bound {
        /// Full lowercase commit revision.
        revision: String,
        /// Whether the source checkout was dirty.
        dirty: bool,
    },
}

/// A deterministic release-binding validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildBindingError {
    /// The explicit packager-provided revision was not a full lowercase SHA.
    InvalidExplicitRevision(String),
    /// Git returned a value that was not a full lowercase SHA.
    InvalidGitRevision(String),
    /// The explicit revision did not identify the checked-out commit.
    RevisionMismatch {
        /// Validated packager-provided revision.
        explicit: String,
        /// Validated `HEAD^{commit}` revision.
        git: String,
    },
}

impl fmt::Display for BuildBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExplicitRevision(revision) => write!(
                formatter,
                "OMNIUS_RELEASE_REVISION must be exactly 40 lowercase hexadecimal characters, got `{revision}`"
            ),
            Self::InvalidGitRevision(revision) => write!(
                formatter,
                "Git HEAD must resolve to exactly 40 lowercase hexadecimal characters, got `{revision}`"
            ),
            Self::RevisionMismatch { explicit, git } => write!(
                formatter,
                "OMNIUS_RELEASE_REVISION `{explicit}` does not match Git HEAD `{git}`"
            ),
        }
    }
}

impl Error for BuildBindingError {}

/// Selects and validates a build binding without consulting process or filesystem state.
pub fn resolve_build_binding(
    explicit_revision: Option<&str>,
    git: Option<&GitSnapshot>,
) -> Result<BuildBinding, BuildBindingError> {
    if let Some(revision) = explicit_revision
        && !revision::is_valid_release_revision(revision)
    {
        return Err(BuildBindingError::InvalidExplicitRevision(
            revision.to_owned(),
        ));
    }

    if let Some(snapshot) = git
        && !revision::is_valid_release_revision(&snapshot.revision)
    {
        return Err(BuildBindingError::InvalidGitRevision(
            snapshot.revision.clone(),
        ));
    }

    match (explicit_revision, git) {
        (Some(explicit), Some(snapshot)) if explicit != snapshot.revision.as_str() => {
            Err(BuildBindingError::RevisionMismatch {
                explicit: explicit.to_owned(),
                git: snapshot.revision.clone(),
            })
        }
        (Some(explicit), Some(snapshot)) => Ok(BuildBinding::Bound {
            revision: explicit.to_owned(),
            dirty: snapshot.dirty,
        }),
        (Some(explicit), None) => Ok(BuildBinding::Bound {
            revision: explicit.to_owned(),
            dirty: false,
        }),
        (None, Some(snapshot)) => Ok(BuildBinding::Bound {
            revision: snapshot.revision.clone(),
            dirty: snapshot.dirty,
        }),
        (None, None) => Ok(BuildBinding::Unbound),
    }
}

/// Reports whether exact porcelain-v1 output contains a source change.
///
/// Cargo creates an untracked `.cargo-ok` marker in Git dependency checkouts;
/// that transport marker is not part of the source tree and does not make a
/// release build dirty.
#[must_use]
pub fn porcelain_status_is_dirty(output: &[u8]) -> bool {
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .any(|line| line != b"?? .cargo-ok")
}
