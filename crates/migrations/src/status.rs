use std::collections::{BTreeMap, BTreeSet};

use omnius_core::SchemaCompatibility;
use sqlx::migrate::Migrator;
use thiserror::Error;

/// Ordered database schema versions supported by one binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaVersionRange {
    /// Oldest schema version on which this binary can operate.
    minimum: i64,
    maximum: i64,
}

impl SchemaVersionRange {
    /// Creates a positive, ordered compatibility range.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidCompatibilityRange`] for non-positive
    /// or reversed bounds.
    pub fn new(minimum: i64, maximum: i64) -> Result<Self, MigrationError> {
        if minimum <= 0 || maximum < minimum {
            return Err(MigrationError::InvalidCompatibilityRange);
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns the oldest supported schema version.
    #[must_use]
    pub const fn minimum(self) -> i64 {
        self.minimum
    }

    /// Returns the newest supported schema version.
    #[must_use]
    pub const fn maximum(self) -> i64 {
        self.maximum
    }
}

impl TryFrom<SchemaCompatibility> for SchemaVersionRange {
    type Error = MigrationError;

    fn try_from(value: SchemaCompatibility) -> Result<Self, Self::Error> {
        let minimum = value
            .minimum
            .parse()
            .map_err(|_| MigrationError::InvalidCompatibilityRange)?;
        let maximum = value
            .maximum
            .parse()
            .map_err(|_| MigrationError::InvalidCompatibilityRange)?;
        Self::new(minimum, maximum)
    }
}

/// Safe operational view of migration history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationStatus {
    /// Highest successfully installed migration, or `None` for a fresh database.
    pub current_version: Option<i64>,
    /// Highest up migration embedded in this binary.
    pub target_version: i64,
    /// Successfully installed migration count.
    pub applied_count: usize,
    /// Embedded migrations not yet installed.
    pub pending_versions: Vec<i64>,
    /// Installed versions absent from this binary's migration source.
    pub unknown_versions: Vec<i64>,
    /// Installed known versions whose released SQL changed.
    pub checksum_mismatches: Vec<i64>,
    /// Known versions missing below the current database version.
    pub history_gaps: Vec<i64>,
    /// Partially installed version, if present.
    pub dirty_version: Option<i64>,
}

impl MigrationStatus {
    /// Verifies that history is sound and the database lies in the binary's range.
    ///
    /// Unknown versions newer than this binary's embedded head are allowed when
    /// the current version remains within the declared range. This is required
    /// for old and new binaries to coexist after an expand-compatible migration.
    ///
    /// # Errors
    ///
    /// Returns a stable compatibility failure for dirty, modified, gapped,
    /// uninitialized, too-old, or too-new schemas.
    pub fn verify(&self, range: SchemaVersionRange) -> Result<(), MigrationError> {
        if let Some(version) = self.dirty_version {
            return Err(MigrationError::Dirty(version));
        }
        if let Some(version) = self.checksum_mismatches.first().copied() {
            return Err(MigrationError::ChecksumMismatch(version));
        }
        if let Some(version) = self.history_gaps.first().copied() {
            return Err(MigrationError::HistoryGap(version));
        }
        if let Some(version) = self
            .unknown_versions
            .iter()
            .find(|version| **version <= self.target_version)
            .copied()
        {
            return Err(MigrationError::MissingMigration(version));
        }
        let Some(current) = self.current_version else {
            return Err(MigrationError::SchemaUninitialized);
        };
        if current < range.minimum {
            return Err(MigrationError::SchemaTooOld {
                current,
                minimum: range.minimum,
            });
        }
        if current > range.maximum {
            return Err(MigrationError::SchemaTooNew {
                current,
                maximum: range.maximum,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct AppliedRow {
    pub(crate) version: i64,
    pub(crate) checksum: Vec<u8>,
    pub(crate) success: bool,
}

pub(crate) fn build_status(
    migrator: &Migrator,
    applied: Vec<AppliedRow>,
) -> Result<MigrationStatus, MigrationError> {
    let known = migrator
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .map(|migration| (migration.version, migration.checksum.as_ref()))
        .collect::<BTreeMap<_, _>>();
    let Some(target_version) = known.keys().next_back().copied() else {
        return Err(MigrationError::NoMigrations);
    };

    let mut successful = BTreeSet::new();
    let mut dirty_version = None;
    let mut unknown_versions = Vec::new();
    let mut checksum_mismatches = Vec::new();
    for row in applied {
        if !row.success {
            dirty_version = Some(row.version);
            continue;
        }
        successful.insert(row.version);
        match known.get(&row.version) {
            Some(checksum) if **checksum != row.checksum => {
                checksum_mismatches.push(row.version);
            }
            None => unknown_versions.push(row.version),
            Some(_) => {}
        }
    }

    let current_version = successful.last().copied();
    let pending_versions = known
        .keys()
        .filter(|version| !successful.contains(version))
        .copied()
        .collect::<Vec<_>>();
    let history_gaps = current_version.map_or_else(Vec::new, |current| {
        pending_versions
            .iter()
            .filter(|version| **version < current)
            .copied()
            .collect()
    });

    Ok(MigrationStatus {
        current_version,
        target_version,
        applied_count: successful.len(),
        pending_versions,
        unknown_versions,
        checksum_mismatches,
        history_gaps,
        dirty_version,
    })
}

/// Stable, credential-free migration and compatibility failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MigrationError {
    /// Migration configuration was invalid.
    #[error("invalid migration configuration")]
    Config,
    /// The binary's schema range was invalid.
    #[error("schema compatibility range must contain positive ordered versions")]
    InvalidCompatibilityRange,
    /// A migration source contains a down migration.
    #[error("migration source contains down migration {version}")]
    DownMigration {
        /// Rejected migration version.
        version: i64,
    },
    /// Application-owned migration version lies outside its reserved range.
    #[error("application migration {version} is outside the reserved version range")]
    ApplicationVersionOutOfRange {
        /// Rejected migration version.
        version: i64,
    },
    /// Two migrations use the same version.
    #[error("migration source contains duplicate version {version}")]
    DuplicateVersion {
        /// Duplicated migration version.
        version: i64,
    },
    /// `SQLx` could not construct a migrator from the validated source.
    #[error("failed to construct combined migration source")]
    Construction,
    /// A migration source must contain at least one up migration.
    #[error("migration source contains no up migrations")]
    NoMigrations,
    /// PostgreSQL could not be acquired or queried.
    #[error("database is unavailable for migration operation")]
    DatabaseUnavailable,
    /// The bounded migration operation expired.
    #[error("migration operation timed out")]
    OperationTimeout,
    /// `SQLx` found a partially applied migration.
    #[error("database migration {0} is partially applied")]
    Dirty(i64),
    /// Released migration SQL was modified after installation.
    #[error("database migration {0} checksum does not match the binary")]
    ChecksumMismatch(i64),
    /// `SQLx` found an applied migration missing from the command source.
    #[error("database migration {0} is absent from the command source")]
    MissingMigration(i64),
    /// A known migration below the current version was never installed.
    #[error("database migration history has a gap at version {0}")]
    HistoryGap(i64),
    /// The database has no installed migration.
    #[error("database schema is not initialized")]
    SchemaUninitialized,
    /// The database predates this binary's supported range.
    #[error("database schema version {current} is older than supported minimum {minimum}")]
    SchemaTooOld {
        /// Installed schema version.
        current: i64,
        /// Oldest supported schema version.
        minimum: i64,
    },
    /// The database is newer than this binary's supported range.
    #[error("database schema version {current} is newer than supported maximum {maximum}")]
    SchemaTooNew {
        /// Installed schema version.
        current: i64,
        /// Newest supported schema version.
        maximum: i64,
    },
    /// Migration execution failed without exposing SQL or credentials.
    #[error("database migration execution failed")]
    Execution,
}
