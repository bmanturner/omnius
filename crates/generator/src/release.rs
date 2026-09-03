use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::revision::is_valid_release_revision;

/// Canonical source repository for every Omnius release identity.
pub const CANONICAL_REPOSITORY: &str = "https://github.com/bmanturner/omnius.git";

/// Version of the executing generator package.
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Immutable identity of one clean, reproducible Omnius release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseIdentity {
    version: String,
    repository: String,
    revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIdentityFields {
    version: String,
    repository: String,
    revision: String,
}

impl ReleaseIdentity {
    /// Constructs an explicit identity for deterministic lifecycle orchestration and tests.
    ///
    /// The version must identify this generator release, the repository must be the canonical
    /// HTTPS URL byte-for-byte, and the revision must be a full lowercase commit SHA.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseIdentityError::InvalidVersion`] when `version` is not semantic,
    /// [`ReleaseIdentityError::InvalidRepository`] when `repository` is not canonical, or
    /// [`ReleaseIdentityError::InvalidRevision`] when `revision` is not a full lowercase SHA.
    pub fn new(
        version: impl Into<String>,
        repository: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, ReleaseIdentityError> {
        let version = version.into();
        let repository = repository.into();
        let revision = revision.into();
        validate_metadata(&version, &repository)?;
        if !is_valid_release_revision(&revision) {
            return Err(ReleaseIdentityError::InvalidRevision(revision));
        }

        Ok(Self {
            version,
            repository,
            revision,
        })
    }

    /// Returns the executing generator's identity only when its build is clean and bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the compile-time release metadata or binding is invalid, dirty, or
    /// unbound.
    pub fn current() -> Result<Self, ReleaseIdentityError> {
        match ReleaseBuildStatus::current()? {
            ReleaseBuildStatus::Clean(identity) => Ok(identity),
            ReleaseBuildStatus::Dirty { revision } => {
                Err(ReleaseIdentityError::DirtyBuild { revision })
            }
            ReleaseBuildStatus::Unbound => Err(ReleaseIdentityError::UnboundBuild),
        }
    }

    /// Returns the generator package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the canonical source repository.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the full lowercase commit revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

impl<'de> Deserialize<'de> for ReleaseIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = ReleaseIdentityFields::deserialize(deserializer)?;
        Self::new(fields.version, fields.repository, fields.revision).map_err(de::Error::custom)
    }
}

/// Read-only release binding observed in the compiled generator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseBuildStatus {
    /// The generator was built from a clean source at a validated immutable revision.
    Clean(ReleaseIdentity),
    /// The revision is valid, but the source had staged, unstaged, or untracked changes.
    Dirty {
        /// Full lowercase commit revision of the dirty checkout.
        revision: String,
    },
    /// Neither source Git metadata nor an explicit packager revision was available.
    Unbound,
}

impl ReleaseBuildStatus {
    /// Reads and validates the compile-time release binding without performing runtime Git I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the compile-time package metadata or release binding is invalid.
    pub fn current() -> Result<Self, ReleaseIdentityError> {
        status_from_build_binding(
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY"),
            option_env!("OMNIUS_BUILD_GIT_REVISION"),
            option_env!("OMNIUS_BUILD_GIT_DIRTY"),
        )
    }

    /// Returns the bound revision for clean or dirty builds.
    #[must_use]
    pub fn revision(&self) -> Option<&str> {
        match self {
            Self::Clean(identity) => Some(identity.revision()),
            Self::Dirty { revision } => Some(revision),
            Self::Unbound => None,
        }
    }

    /// Reports whether this status can yield a mutation-capable release identity.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean(_))
    }
}

/// Release metadata or build-binding validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseIdentityError {
    /// The supplied version is not a valid semantic version.
    InvalidVersion(String),
    /// The supplied repository is not the canonical HTTPS repository.
    InvalidRepository {
        /// Required canonical repository.
        expected: &'static str,
        /// Supplied repository.
        actual: String,
    },
    /// The revision is not exactly 40 lowercase ASCII hexadecimal characters.
    InvalidRevision(String),
    /// The compiled build binding has an internally inconsistent dirty flag or revision.
    InvalidBuildBinding,
    /// The source checkout was dirty when the generator was compiled.
    DirtyBuild {
        /// Full lowercase commit revision of the dirty checkout.
        revision: String,
    },
    /// The generator was compiled without a revision binding.
    UnboundBuild,
}

impl fmt::Display for ReleaseIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(version) => write!(
                formatter,
                "release version must be a valid semantic version, got `{version}`"
            ),
            Self::InvalidRepository { expected, actual } => write!(
                formatter,
                "release repository must be exactly `{expected}`, got `{actual}`"
            ),
            Self::InvalidRevision(revision) => write!(
                formatter,
                "release revision must be exactly 40 lowercase hexadecimal characters, got `{revision}`"
            ),
            Self::InvalidBuildBinding => formatter
                .write_str("compiled release binding has an inconsistent revision or dirty marker"),
            Self::DirtyBuild { revision } => write!(
                formatter,
                "generator release `{revision}` was built from a dirty source checkout"
            ),
            Self::UnboundBuild => {
                formatter.write_str("generator build is not bound to an immutable release revision")
            }
        }
    }
}

impl Error for ReleaseIdentityError {}

fn validate_metadata(version: &str, repository: &str) -> Result<(), ReleaseIdentityError> {
    if semver::Version::parse(version).is_err() {
        return Err(ReleaseIdentityError::InvalidVersion(version.to_owned()));
    }
    if repository != CANONICAL_REPOSITORY {
        return Err(ReleaseIdentityError::InvalidRepository {
            expected: CANONICAL_REPOSITORY,
            actual: repository.to_owned(),
        });
    }
    Ok(())
}

fn status_from_build_binding(
    version: &str,
    repository: &str,
    revision: Option<&str>,
    dirty: Option<&str>,
) -> Result<ReleaseBuildStatus, ReleaseIdentityError> {
    validate_metadata(version, repository)?;

    match (revision, dirty) {
        (None, None | Some("false")) => Ok(ReleaseBuildStatus::Unbound),
        (Some(revision), Some("false")) => {
            ReleaseIdentity::new(version, repository, revision).map(ReleaseBuildStatus::Clean)
        }
        (Some(revision), Some("true")) if is_valid_release_revision(revision) => {
            Ok(ReleaseBuildStatus::Dirty {
                revision: revision.to_owned(),
            })
        }
        (Some(revision), Some("true")) => {
            Err(ReleaseIdentityError::InvalidRevision(revision.to_owned()))
        }
        _ => Err(ReleaseIdentityError::InvalidBuildBinding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    fn test_value<T, E>(result: Result<T, E>, context: &str) -> T {
        let Ok(value) = result else {
            panic!("{context}");
        };
        value
    }

    #[test]
    fn release_identity_serde_should_be_strict_and_validated() {
        let identity = test_value(
            ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, REVISION),
            "identity should be valid",
        );
        let encoded = test_value(toml::to_string(&identity), "identity should serialize");
        let decoded = test_value(
            toml::from_str::<ReleaseIdentity>(&encoded),
            "identity should deserialize",
        );
        assert_eq!(decoded, identity);

        let unknown = format!("{encoded}unknown = true\n");
        assert!(toml::from_str::<ReleaseIdentity>(&unknown).is_err());

        let invalid_version = encoded.replacen(GENERATOR_VERSION, "not-semver", 1);
        assert!(toml::from_str::<ReleaseIdentity>(&invalid_version).is_err());

        let alternate_repository = encoded.replacen(CANONICAL_REPOSITORY, "ssh://example", 1);
        assert!(toml::from_str::<ReleaseIdentity>(&alternate_repository).is_err());

        let uppercase_revision = encoded.replacen(REVISION, &REVISION.to_ascii_uppercase(), 1);
        assert!(toml::from_str::<ReleaseIdentity>(&uppercase_revision).is_err());
    }

    #[test]
    fn status_should_preserve_a_dirty_revision_without_yielding_an_identity() {
        let status = test_value(
            status_from_build_binding(
                GENERATOR_VERSION,
                CANONICAL_REPOSITORY,
                Some(REVISION),
                Some("true"),
            ),
            "deterministic binding should be valid",
        );

        assert_eq!(
            status,
            ReleaseBuildStatus::Dirty {
                revision: REVISION.to_owned()
            }
        );
    }

    #[test]
    fn status_should_represent_a_packaged_unbound_build() {
        let status = test_value(
            status_from_build_binding(GENERATOR_VERSION, CANONICAL_REPOSITORY, None, Some("false")),
            "deterministic binding should be valid",
        );

        assert_eq!(status, ReleaseBuildStatus::Unbound);
    }

    #[test]
    fn status_should_reject_an_inconsistent_binding() {
        let result = status_from_build_binding(
            GENERATOR_VERSION,
            CANONICAL_REPOSITORY,
            Some(REVISION),
            None,
        );
        let Err(error) = result else {
            panic!("a bound revision requires an explicit dirty marker");
        };

        assert_eq!(error, ReleaseIdentityError::InvalidBuildBinding);
    }
}
