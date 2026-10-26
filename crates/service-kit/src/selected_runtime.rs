//! Selected runtime resources, their configuration, and migration commands.

use serde::{Deserialize, Serialize};

#[cfg(feature = "http")]
use crate::ApplicationRuntime;
use crate::{
    ApplicationContributions, ApplicationFactoryError, CompositionError, SchemaCompatibility,
};

/// Strict feature-gated configuration for selected runtime modules.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SelectedRuntimeConfig {
    /// PostgreSQL pool policy.
    #[cfg(feature = "postgres")]
    #[serde(deserialize_with = "deserialize_postgres_config")]
    pub postgres: omnius_postgres::PostgresConfig,
    /// Startup and operator migration policy.
    #[cfg(feature = "migrations")]
    pub migrations: omnius_migrations::MigrationConfig,
    /// Transactional idempotency policy.
    #[cfg(feature = "idempotency")]
    pub idempotency: omnius_idempotency::IdempotencyConfig,
    /// Exact document and docs exposure policy.
    #[cfg(feature = "openapi")]
    pub openapi: omnius_openapi::OpenApiConfig,
    /// Restricted outbound-client policy.
    #[cfg(feature = "outbound-http")]
    pub outbound_http: omnius_outbound_http::OutboundHttpConfig,
}

#[cfg(feature = "postgres")]
fn deserialize_postgres_config<'de, D>(
    deserializer: D,
) -> Result<omnius_postgres::PostgresConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let config = omnius_postgres::PostgresConfig::deserialize(deserializer)?;
    config
        .validate_for(omnius_config::DeploymentEnvironment::Development)
        .map_err(serde::de::Error::custom)?;
    Ok(config)
}

#[cfg(feature = "migrations")]
fn selected_migration_runner(
    pool: &omnius_postgres::PostgresPool,
    migrations: omnius_migrations::PreparedMigrations,
    config: &SelectedRuntimeConfig,
    deployment: omnius_config::DeploymentEnvironment,
    schema: SchemaCompatibility,
) -> Result<omnius_migrations::MigrationRunner, CompositionError> {
    let range = omnius_migrations::SchemaVersionRange::try_from(schema)
        .map_err(|error| CompositionError::construction("migrations", error))?;
    omnius_migrations::MigrationRunner::new(
        pool.clone(),
        migrations,
        range,
        config.migrations,
        deployment,
    )
    .map_err(|error| CompositionError::construction("migrations", error))
}

#[cfg(feature = "postgres")]
async fn connect_postgres(
    config: &SelectedRuntimeConfig,
    deployment: omnius_config::DeploymentEnvironment,
    #[cfg(feature = "migrations")] schema: SchemaCompatibility,
    #[cfg(feature = "migrations")] application_migrations: omnius_migrations::ApplicationMigrations,
    #[cfg(feature = "migrations")] apply_startup_policy: bool,
) -> Result<omnius_postgres::PostgresPool, CompositionError> {
    #[cfg(feature = "migrations")]
    let migrations =
        omnius_migrations::prepare_migrations(&omnius_migrations::MIGRATOR, application_migrations)
            .await
            .map_err(|error| CompositionError::construction("migrations", error))?;
    let pool = omnius_postgres::PostgresPool::connect(&config.postgres, deployment)
        .await
        .map_err(|error| CompositionError::construction("postgres", error))?;
    #[cfg(feature = "migrations")]
    {
        let runner = selected_migration_runner(&pool, migrations, config, deployment, schema)?;
        if apply_startup_policy {
            runner
                .apply_startup_policy()
                .await
                .map_err(|error| CompositionError::construction("migrations", error))?;
        }
    }
    Ok(pool)
}

/// Connected resources selected by compile-time module features.
#[derive(Default)]
pub struct SelectedRuntime {
    #[cfg(feature = "postgres")]
    pub(crate) postgres: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    pub(crate) idempotency_store: Option<omnius_idempotency::PostgresIdempotencyStore>,
    #[cfg(feature = "openapi")]
    pub(crate) openapi_config: Option<omnius_openapi::OpenApiConfig>,
    #[cfg(feature = "outbound-http")]
    pub(crate) outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
}

impl SelectedRuntime {
    /// Constructs non-I/O runtime defaults for generated in-process handler tests.
    ///
    /// External resources remain absent so profiles requiring PostgreSQL or
    /// outbound clients continue to fail closed.
    #[must_use]
    pub fn for_in_process_tests() -> Self {
        let mut runtime = Self::default();
        #[cfg(feature = "openapi")]
        {
            runtime.openapi_config = Some(omnius_openapi::OpenApiConfig::default());
        }
        runtime
    }

    /// Constructs only the provider resources selected by Cargo features.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when a selected provider cannot be
    /// constructed or when migration preparation or startup policy application
    /// fails.
    pub async fn connect(
        #[cfg(any(feature = "postgres", feature = "openapi", feature = "outbound-http"))]
        config: &SelectedRuntimeConfig,
        #[cfg(not(any(feature = "postgres", feature = "openapi", feature = "outbound-http")))]
        _config: &SelectedRuntimeConfig,
        #[cfg(feature = "postgres")] deployment: omnius_config::DeploymentEnvironment,
        #[cfg(not(feature = "postgres"))] _deployment: omnius_config::DeploymentEnvironment,
        #[cfg(feature = "migrations")] schema: SchemaCompatibility,
        #[cfg(not(feature = "migrations"))] _schema: SchemaCompatibility,
        #[cfg(feature = "migrations")]
        application_migrations: omnius_migrations::ApplicationMigrations,
        #[cfg(feature = "migrations")] apply_startup_policy: bool,
        #[cfg(not(feature = "migrations"))] _apply_startup_policy: bool,
    ) -> Result<Self, CompositionError> {
        #[cfg(any(feature = "postgres", feature = "openapi", feature = "outbound-http"))]
        let mut runtime = Self::default();
        #[cfg(not(any(feature = "postgres", feature = "openapi", feature = "outbound-http")))]
        let runtime = Self::default();
        #[cfg(feature = "postgres")]
        {
            #[cfg(feature = "migrations")]
            let pool = connect_postgres(
                config,
                deployment,
                schema,
                application_migrations,
                apply_startup_policy,
            )
            .await?;
            #[cfg(not(feature = "migrations"))]
            let pool = connect_postgres(config, deployment).await?;
            #[cfg(feature = "idempotency")]
            {
                runtime.idempotency_store = Some(
                    omnius_idempotency::PostgresIdempotencyStore::new(config.idempotency)
                        .map_err(|error| CompositionError::construction("idempotency", error))?,
                );
            }
            runtime.postgres = Some(pool);
        }
        #[cfg(feature = "openapi")]
        {
            runtime.openapi_config = Some(config.openapi);
        }
        #[cfg(feature = "outbound-http")]
        {
            let clients = omnius_outbound_http::OutboundHttpClients::new(&config.outbound_http)
                .map_err(|error| CompositionError::construction("outbound-http", error))?;
            runtime.outbound_http = Some(std::sync::Arc::new(clients));
        }
        Ok(runtime)
    }
}

/// Explicit database command selected by the process CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedMigrationCommand {
    /// Apply pending embedded migrations.
    Migrate,
    /// Inspect migration state without mutation.
    Status,
}

/// Stable JSON shape returned by generated migration commands.
#[derive(Debug, Serialize)]
pub struct MigrationStatusDocument {
    current_version: Option<i64>,
    target_version: i64,
    applied_count: usize,
    pending_versions: Vec<i64>,
    unknown_versions: Vec<i64>,
    checksum_mismatches: Vec<i64>,
    history_gaps: Vec<i64>,
    dirty_version: Option<i64>,
}

/// Executes a selected migration command and closes its dedicated pool.
///
/// # Errors
///
/// Returns [`CompositionError`] when migrations are not compiled into the
/// selected runtime or when migration preparation, connection, execution, or
/// pool shutdown fails.
pub async fn execute_selected_migration(
    #[cfg(feature = "migrations")] config: &SelectedRuntimeConfig,
    #[cfg(not(feature = "migrations"))] _config: &SelectedRuntimeConfig,
    #[cfg(feature = "migrations")] deployment: omnius_config::DeploymentEnvironment,
    #[cfg(not(feature = "migrations"))] _deployment: omnius_config::DeploymentEnvironment,
    #[cfg(feature = "migrations")] schema: SchemaCompatibility,
    #[cfg(not(feature = "migrations"))] _schema: SchemaCompatibility,
    #[cfg(feature = "migrations")] _profile: &'static str,
    #[cfg(not(feature = "migrations"))] profile: &'static str,
    #[cfg(feature = "migrations")] application_migrations: omnius_migrations::ApplicationMigrations,
    command: SelectedMigrationCommand,
) -> Result<MigrationStatusDocument, CompositionError> {
    #[cfg(feature = "migrations")]
    {
        let migrations = omnius_migrations::prepare_migrations(
            &omnius_migrations::MIGRATOR,
            application_migrations,
        )
        .await
        .map_err(|error| CompositionError::construction("migrations", error))?;
        let pool = omnius_postgres::PostgresPool::connect(&config.postgres, deployment)
            .await
            .map_err(|error| CompositionError::construction("postgres", error))?;
        let operation = async {
            let runner = selected_migration_runner(&pool, migrations, config, deployment, schema)?;
            let command = match command {
                SelectedMigrationCommand::Migrate => omnius_migrations::MigrationCommand::Migrate,
                SelectedMigrationCommand::Status => omnius_migrations::MigrationCommand::Status,
            };
            let output = runner
                .execute(command)
                .await
                .map_err(|error| CompositionError::construction("migrations", error))?;
            let status = match output {
                omnius_migrations::MigrationCommandOutput::Migrated(status)
                | omnius_migrations::MigrationCommandOutput::Status(status) => status,
            };
            Ok(MigrationStatusDocument {
                current_version: status.current_version,
                target_version: status.target_version,
                applied_count: status.applied_count,
                pending_versions: status.pending_versions,
                unknown_versions: status.unknown_versions,
                checksum_mismatches: status.checksum_mismatches,
                history_gaps: status.history_gaps,
                dirty_version: status.dirty_version,
            })
        }
        .await;
        let close = pool
            .close()
            .await
            .map_err(|error| CompositionError::construction("postgres", error));
        match (operation, close) {
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(status), Ok(())) => Ok(status),
        }
    }
    #[cfg(not(feature = "migrations"))]
    {
        let command = match command {
            SelectedMigrationCommand::Migrate => "migrate",
            SelectedMigrationCommand::Status => "migration-status",
        };
        Err(CompositionError::command_unavailable(profile, command))
    }
}

/// Selected-runtime installation for application contributions.
impl ApplicationContributions {
    /// Supplies resources constructed from feature-gated selected configuration.
    ///
    /// The one-shot application factory is awaited after selected resources
    /// exist and before registrar validation begins.
    ///
    /// # Errors
    ///
    /// Returns the synchronous or asynchronous application factory failure.
    #[cfg(any(feature = "http", feature = "postgres", feature = "outbound-http"))]
    pub async fn with_selected_runtime(
        mut self,
        #[cfg(any(feature = "postgres", feature = "openapi", feature = "outbound-http"))]
        runtime: SelectedRuntime,
        #[cfg(not(any(feature = "postgres", feature = "openapi", feature = "outbound-http")))]
        _runtime: SelectedRuntime,
        application_config: serde_json::Value,
        deployment: omnius_config::DeploymentEnvironment,
    ) -> Result<Self, ApplicationFactoryError> {
        #[cfg(feature = "http")]
        let application_runtime = ApplicationRuntime {
            application_config: Some(application_config),
            deployment,
            #[cfg(feature = "postgres")]
            postgres_pool: runtime.postgres.clone(),
            #[cfg(feature = "idempotency")]
            idempotency_store: runtime.idempotency_store,
            #[cfg(feature = "outbound-http")]
            outbound_http: runtime.outbound_http.clone(),
        };
        #[cfg(feature = "postgres")]
        {
            self.postgres_pool = runtime.postgres;
        }
        #[cfg(feature = "idempotency")]
        {
            self.idempotency_store = runtime.idempotency_store;
        }
        #[cfg(feature = "openapi")]
        {
            self.openapi_config = runtime.openapi_config;
        }
        #[cfg(feature = "outbound-http")]
        {
            self.outbound_http = runtime.outbound_http;
        }
        #[cfg(feature = "http")]
        if let Some(factory) = self.async_application_factory.take() {
            let mut output = factory(application_runtime).await?;
            if output.application_extension.is_some() {
                self.application_extension = output.application_extension.take();
            }
            #[cfg(any(
                feature = "auth-http",
                feature = "auth-password",
                feature = "auth-session-postgres",
                feature = "auth-session-redis",
                feature = "auth-oidc",
                feature = "auth-api-key",
                feature = "auth-webauthn",
                feature = "auth-totp",
                feature = "auth-oauth-server",
                test
            ))]
            if output.auth.is_some() {
                self.auth = output.auth.take();
            }
            #[cfg(any(feature = "jobs-core", test))]
            if output.jobs.is_some() {
                self.jobs = output.jobs.take();
            }
            #[cfg(feature = "email")]
            if output.email_output.is_some() {
                self.email_output = output.email_output.take();
            }
        } else if let Some(factory) = self.application_extension_factory.take() {
            self.application_extension = Some(factory(application_runtime)?);
        }
        Ok(self)
    }

    #[cfg(not(any(feature = "http", feature = "postgres", feature = "outbound-http")))]
    /// Returns the unchanged contribution set when no provider resource feature is selected.
    pub async fn with_selected_runtime(
        self,
        _runtime: SelectedRuntime,
        _application_config: serde_json::Value,
        _deployment: omnius_config::DeploymentEnvironment,
    ) -> Result<Self, ApplicationFactoryError> {
        Ok(self)
    }
}
