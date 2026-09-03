//! Explicit `SQLx` migration commands and startup schema compatibility checks.
//!
//! Normal production server startup verifies compatibility only. Schema changes
//! run through [`MigrationCommand::Migrate`], which retains `SQLx`'s PostgreSQL
//! advisory lock and immutable checksum validation.

mod config;
mod prepared;
mod runner;
mod status;

pub use config::{MigrationConfig, MigrationConfigError};
pub use prepared::{
    APPLICATION_MIGRATION_MAXIMUM, APPLICATION_MIGRATION_MINIMUM, ApplicationMigrations,
    PreparedMigrations, prepare_migrations,
};
pub use runner::{MigrationCommand, MigrationCommandOutput, MigrationRunner};
pub use sqlx::{migrate, migrate::Migrator};
pub use status::{MigrationError, MigrationStatus, SchemaVersionRange};

include!(concat!(env!("OUT_DIR"), "/current_schema_version.rs"));

/// Embedded, forward-only framework migration history.
pub static MIGRATOR: Migrator = migrate!("../../migrations");

pub(crate) use status::{AppliedRow, build_status};
