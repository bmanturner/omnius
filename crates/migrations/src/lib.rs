//! Explicit `SQLx` migration commands and startup schema compatibility checks.
//!
//! Normal production server startup verifies compatibility only. Schema changes
//! run through [`MigrationCommand::Migrate`], which retains `SQLx`'s PostgreSQL
//! advisory lock and immutable checksum validation.

mod config;
mod runner;
mod status;

pub use config::{MigrationConfig, MigrationConfigError};
pub use runner::{MigrationCommand, MigrationCommandOutput, MigrationRunner};
pub use status::{MigrationError, MigrationStatus, SchemaVersionRange};

pub(crate) use status::{AppliedRow, build_status};
