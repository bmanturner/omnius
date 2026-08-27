use std::time::Duration;

use omnius_config::DeploymentEnvironment;
use serde::Deserialize;
use thiserror::Error;

const MIN_OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_hours(24);

/// Explicit migration execution policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MigrationConfig {
    /// Allows schema changes during application startup in local and test environments.
    pub run_on_startup: bool,
    /// Bounds one status, compatibility, or migration operation.
    #[serde(with = "humantime_serde")]
    pub operation_timeout: Duration,
}

impl MigrationConfig {
    /// Validates environment and deadline policy.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationConfigError`] when production auto-migration is enabled
    /// or the operation deadline is outside the fixed safety range.
    pub fn validate_for(
        self,
        deployment: DeploymentEnvironment,
    ) -> Result<(), MigrationConfigError> {
        if deployment == DeploymentEnvironment::Production && self.run_on_startup {
            return Err(MigrationConfigError::ProductionAutoMigration);
        }
        if !(MIN_OPERATION_TIMEOUT..=MAX_OPERATION_TIMEOUT).contains(&self.operation_timeout) {
            return Err(MigrationConfigError::InvalidOperationTimeout);
        }
        Ok(())
    }
}

/// Stable migration configuration failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MigrationConfigError {
    /// Production schema changes must use the dedicated migration command.
    #[error("production startup cannot run database migrations")]
    ProductionAutoMigration,
    /// Migration operations must complete within a bounded interval.
    #[error("migration operation timeout must be between 1 second and 24 hours")]
    InvalidOperationTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rejects_startup_migrations() {
        let config = MigrationConfig {
            run_on_startup: true,
            operation_timeout: Duration::from_secs(60),
        };
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Err(MigrationConfigError::ProductionAutoMigration)
        );
        assert!(config.validate_for(DeploymentEnvironment::Test).is_ok());
    }

    #[test]
    fn operation_timeout_is_bounded() {
        let config = MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_millis(999),
        };
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(MigrationConfigError::InvalidOperationTimeout)
        );
    }
}
