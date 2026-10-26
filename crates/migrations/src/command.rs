use omnius_config::DeploymentEnvironment;
use omnius_core::SchemaCompatibility;
use omnius_postgres::PostgresPool;

use crate::{
    MIGRATOR, MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationError,
    MigrationRunner, MigrationStatus, SchemaVersionRange,
};

/// Runs one explicit framework migration command on an already-connected pool
/// and returns the resulting schema status.
///
/// The caller owns the pool lifecycle, including closing it afterwards.
///
/// # Errors
///
/// Returns [`MigrationError`] for an invalid schema range, unsafe migration
/// policy for `deployment`, or a failed migration command.
pub async fn execute_migration_command(
    pool: &PostgresPool,
    schema: SchemaCompatibility,
    config: MigrationConfig,
    deployment: DeploymentEnvironment,
    command: MigrationCommand,
) -> Result<MigrationStatus, MigrationError> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::try_from(schema)?,
        config,
        deployment,
    )?;
    Ok(match runner.execute(command).await? {
        MigrationCommandOutput::Migrated(status) | MigrationCommandOutput::Status(status) => status,
    })
}
