use std::time::{Duration, Instant};

use rsk_config::DeploymentEnvironment;
use rsk_postgres::{PostgresConnection, PostgresPool};
use sqlx::{migrate::Migrator, query_as, query_scalar};

use crate::{
    AppliedRow, MigrationConfig, MigrationError, MigrationStatus, SchemaVersionRange, build_status,
};

/// Explicit operational migration actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationCommand {
    /// Apply all pending forward migrations under `SQLx`'s database advisory lock.
    Migrate,
    /// Read migration state without creating or changing migration history.
    Status,
}

/// Result of an explicit migration action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationCommandOutput {
    /// Migrations are at the embedded head.
    Migrated(MigrationStatus),
    /// Current read-only migration state.
    Status(MigrationStatus),
}

/// Thin, observable adapter over one deterministic `SQLx` migrator.
pub struct MigrationRunner<'migration> {
    pool: PostgresPool,
    migrator: &'migration Migrator,
    range: SchemaVersionRange,
    config: MigrationConfig,
}

impl<'migration> MigrationRunner<'migration> {
    /// Creates a runner after validating deployment and schema policy.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError`] for unsafe startup policy, invalid schema
    /// bounds, or an empty migration source.
    pub fn new(
        pool: PostgresPool,
        migrator: &'migration Migrator,
        range: SchemaVersionRange,
        config: MigrationConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<Self, MigrationError> {
        config
            .validate_for(deployment)
            .map_err(|_| MigrationError::Config)?;
        let target = migrator
            .iter()
            .filter(|migration| !migration.migration_type.is_down_migration())
            .map(|migration| migration.version)
            .max()
            .ok_or(MigrationError::NoMigrations)?;
        if target < range.minimum() || target > range.maximum() {
            return Err(MigrationError::InvalidCompatibilityRange);
        }
        Ok(Self {
            pool,
            migrator,
            range,
            config,
        })
    }

    /// Executes a dedicated operational command.
    ///
    /// `Migrate` is explicit in every environment; `run_on_startup` controls
    /// only [`Self::apply_startup_policy`].
    ///
    /// # Errors
    ///
    /// Returns a stable migration, compatibility, database, or timeout error.
    pub async fn execute(
        &self,
        command: MigrationCommand,
    ) -> Result<MigrationCommandOutput, MigrationError> {
        match command {
            MigrationCommand::Migrate => self.run().await.map(MigrationCommandOutput::Migrated),
            MigrationCommand::Status => self.status().await.map(MigrationCommandOutput::Status),
        }
    }

    /// Applies explicit local/test startup policy, otherwise only verifies.
    ///
    /// # Errors
    ///
    /// Returns a stable migration or compatibility failure.
    pub async fn apply_startup_policy(&self) -> Result<MigrationStatus, MigrationError> {
        if self.config.run_on_startup {
            self.run().await
        } else {
            self.verify_compatibility().await
        }
    }

    /// Applies all pending forward migrations under `SQLx` locking.
    ///
    /// # Errors
    ///
    /// Returns a bounded stable error. SQL, paths, checksums, and credentials
    /// are never retained in the error.
    pub async fn run(&self) -> Result<MigrationStatus, MigrationError> {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + self.config.operation_timeout;
        let acquisition = tokio::time::timeout_at(deadline, self.pool.acquire()).await;
        let mut connection = match acquisition {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) => {
                let result = Err(MigrationError::DatabaseUnavailable);
                record_operation("migrate", result_label(&result), started.elapsed());
                return result;
            }
            Err(_) => {
                let result = Err(MigrationError::OperationTimeout);
                record_operation("migrate", result_label(&result), started.elapsed());
                return result;
            }
        };
        let migration =
            tokio::time::timeout_at(deadline, self.migrator.run(&mut *connection)).await;
        let result = match migration {
            Ok(Ok(())) => {
                drop(connection);
                tokio::time::timeout_at(deadline, self.status_unbounded())
                    .await
                    .unwrap_or(Err(MigrationError::OperationTimeout))
            }
            Ok(Err(error)) => {
                let mapped = map_migrate_error(&error);
                discard_tainted(connection);
                Err(mapped)
            }
            Err(_) => {
                discard_tainted(connection);
                Err(MigrationError::OperationTimeout)
            }
        };
        record_operation("migrate", result_label(&result), started.elapsed());
        result
    }

    /// Reads status without creating `_sqlx_migrations` on a fresh database.
    ///
    /// # Errors
    ///
    /// Returns a bounded stable database or timeout error.
    pub async fn status(&self) -> Result<MigrationStatus, MigrationError> {
        let started = Instant::now();
        let result = tokio::time::timeout(self.config.operation_timeout, self.status_unbounded())
            .await
            .unwrap_or(Err(MigrationError::OperationTimeout));
        record_operation("status", result_label(&result), started.elapsed());
        result
    }

    /// Verifies migration history and the binary's supported schema range.
    ///
    /// # Errors
    ///
    /// Returns a stable dirty/checksum/gap/range/database/timeout failure.
    pub async fn verify_compatibility(&self) -> Result<MigrationStatus, MigrationError> {
        let started = Instant::now();
        let result = async {
            let status = self.status().await?;
            status.verify(self.range)?;
            Ok(status)
        }
        .await;
        record_operation("compatibility", result_label(&result), started.elapsed());
        result
    }

    async fn status_unbounded(&self) -> Result<MigrationStatus, MigrationError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| MigrationError::DatabaseUnavailable)?;
        let exists = query_scalar::<_, bool>("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| MigrationError::DatabaseUnavailable)?;
        let rows = if exists {
            query_as::<_, (i64, Vec<u8>, bool)>(
                "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version",
            )
            .fetch_all(&mut *connection)
            .await
            .map_err(|_| MigrationError::DatabaseUnavailable)?
            .into_iter()
            .map(|(version, checksum, success)| AppliedRow {
                version,
                checksum,
                success,
            })
            .collect()
        } else {
            Vec::new()
        };
        build_status(self.migrator, rows)
    }
}

impl std::fmt::Debug for MigrationRunner<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MigrationRunner")
            .field("range", &self.range)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
fn discard_tainted(connection: PostgresConnection) {
    drop(tokio::spawn(async move {
        let _ = connection.discard().await;
    }));
}

fn map_migrate_error(error: &sqlx::migrate::MigrateError) -> MigrationError {
    match error {
        sqlx::migrate::MigrateError::Dirty(version) => MigrationError::Dirty(*version),
        sqlx::migrate::MigrateError::VersionMismatch(version) => {
            MigrationError::ChecksumMismatch(*version)
        }
        sqlx::migrate::MigrateError::VersionMissing(version) => {
            MigrationError::MissingMigration(*version)
        }
        _ => MigrationError::Execution,
    }
}

fn result_label<T>(result: &Result<T, MigrationError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(MigrationError::OperationTimeout) => "timeout",
        Err(
            MigrationError::SchemaUninitialized
            | MigrationError::SchemaTooOld { .. }
            | MigrationError::SchemaTooNew { .. },
        ) => "incompatible",
        Err(_) => "error",
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!("rsk_migrations_operations_total", "operation" => operation, "result" => result)
        .increment(1);
    metrics::histogram!("rsk_migrations_operation_duration_seconds", "operation" => operation)
        .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_error_mapping_does_not_retain_database_errors() {
        let error = map_migrate_error(&sqlx::migrate::MigrateError::VersionMismatch(7));
        assert_eq!(error, MigrationError::ChecksumMismatch(7));
    }
}
