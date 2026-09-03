//! Static application composition for generated services.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::Duration,
};

#[cfg(any(
    feature = "admin",
    feature = "auth-password",
    feature = "auth-session-postgres",
    feature = "auth-session-redis",
    feature = "auth-oidc",
    feature = "auth-api-key",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "auth-oauth-server",
    feature = "billing",
    feature = "feature-flags",
    feature = "graphql",
    feature = "grpc",
    feature = "inbox",
    feature = "jobs-core",
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    feature = "mcp-apps",
    feature = "mcp-transport-http",
    feature = "mcp-server-core",
    feature = "mcp-auth-enterprise",
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    feature = "mcp-tasks",
    feature = "outbox",
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    feature = "scheduler",
    feature = "search-meilisearch",
    feature = "object-storage",
    feature = "webhooks-inbound",
    feature = "webhooks-svix",
    test
))]
use std::sync::Arc;

use axum::Router;
use omnius_health::HealthCheckSpec;
use omnius_runtime::{Criticality, TaskSpec};
use serde::{Deserialize, Serialize};

pub use omnius_core::{
    BuildMetadata, BuildMetadataInput, InvalidBuildMetadata, ProviderMetadata, SchemaCompatibility,
};

/// Configuration loading APIs used by generated process glue.
pub mod config {
    pub use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment};
}

/// Health lifecycle APIs used by generated process glue.
pub mod health {
    pub use omnius_health::{HealthBuilder, HealthConfig, HealthService};
}

/// HTTP shell APIs used by generated process glue.
#[cfg(feature = "http")]
pub mod http {
    pub use omnius_http::{HttpShell, HttpShellConfig, StaticDelivery, StaticDeliveryConfig};

    /// HTTP server lifecycle APIs used by generated process glue.
    pub mod server {
        pub use omnius_http::server::{
            ConnectionMode, HttpServer, HttpServerConfig, PeerAddressMode,
        };
    }
}

/// Runtime supervision APIs used by generated process glue.
pub mod runtime {
    pub use omnius_runtime::{RegisterError, StartError, Supervisor, TaskSpec, TerminationSignals};
}

/// Telemetry lifecycle APIs used by generated process glue.
#[cfg(feature = "telemetry")]
pub mod telemetry {
    pub use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard, bootstrap};
}

#[cfg(feature = "idempotency")]
pub mod idempotency {
    //! Selected idempotency provider API.

    pub use omnius_idempotency::*;
}

#[cfg(feature = "migrations")]
pub mod migrations {
    //! Selected migration provider API.

    pub use omnius_migrations::{
        APPLICATION_MIGRATION_MAXIMUM, APPLICATION_MIGRATION_MINIMUM, ApplicationMigrations,
        CURRENT_SCHEMA_VERSION, FRAMEWORK_SCHEMA_HEAD, FRAMEWORK_SCHEMA_MINIMUM, MIGRATOR,
        MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationConfigError,
        MigrationError, MigrationRunner, MigrationStatus, Migrator, PreparedMigrations,
        SchemaVersionRange, framework_schema_compatibility, prepare_migrations,
    };
    pub use omnius_migrations_macros::migrate;
}

#[doc(hidden)]
#[cfg(feature = "migrations")]
pub mod migrate {
    //! SQLx migration types used by the hygienic embedding macro.

    pub use sqlx::migrate::*;
}

#[cfg(feature = "postgres")]
pub mod postgres {
    //! Selected PostgreSQL provider API.

    pub use omnius_postgres::*;
}

#[cfg(feature = "test-support")]
pub mod test_support {
    //! Selected integration-test support API.

    pub use omnius_test_support::*;
}

#[cfg(feature = "http")]
pub use omnius_http::ExpectedOperation;

mod catalog;
mod modules;
pub use catalog::{ApplicationRequirement, SelectedModuleContract};

/// Immutable inputs generated from the resolved profile selection.
#[derive(Clone, Copy, Debug)]
pub struct CompositionInput {
    /// Selected profile ID.
    pub profile: &'static str,
    /// Selected module IDs in prerequisite-first order.
    pub modules: &'static [&'static str],
    /// Selected provider slots and modules.
    pub providers: &'static [ProviderMetadata],
    #[cfg(any(feature = "core", test))]
    /// Root-owned canonical contracts for the compiled feature set.
    contracts: &'static [SelectedModuleContract],
    /// Runtime-toggle modules explicitly disabled by configuration.
    pub runtime_disabled_modules: &'static [&'static str],
}
impl CompositionInput {
    /// Builds input from generator-owned profile metadata and contracts.
    #[must_use]
    pub const fn generated(
        profile: &'static str,
        modules: &'static [&'static str],
        providers: &'static [ProviderMetadata],
        runtime_disabled_modules: &'static [&'static str],
    ) -> Self {
        Self {
            profile,
            modules,
            providers,
            #[cfg(any(feature = "core", test))]
            contracts: catalog::COMPILED_CONTRACTS,
            runtime_disabled_modules,
        }
    }
}
/// Returns whether any selected module requires an application-owned contribution.
#[must_use]
pub fn selected_requires_application_contributions() -> bool {
    catalog::COMPILED_CONTRACTS
        .iter()
        .any(|contract| !contract.application_requirements.is_empty())
}

/// Configuration for the application-owned local rate limit.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRateLimitConfig {
    /// Whether the selected runtime-toggle limiter is active.
    pub enabled: bool,
    /// Time required to replenish one request token.
    #[serde(with = "humantime_serde")]
    pub replenish_every: Duration,
    /// Maximum immediately available request tokens.
    pub burst_size: u32,
    /// Hard bound on in-memory identity buckets.
    pub identity_buckets: u32,
}

/// Strict feature-gated configuration for selected runtime modules.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    postgres: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    idempotency_store: Option<omnius_idempotency::PostgresIdempotencyStore>,
    #[cfg(feature = "openapi")]
    openapi_config: Option<omnius_openapi::OpenApiConfig>,
    #[cfg(feature = "outbound-http")]
    outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
}

impl SelectedRuntime {
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

/// Stable failure returned while constructing an application extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationExtensionError {
    /// The selected profile did not construct a PostgreSQL pool.
    MissingPostgresPool,
    /// The selected profile did not construct an idempotency store.
    MissingIdempotencyStore,
}

impl fmt::Display for ApplicationExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPostgresPool => {
                formatter.write_str("application extension requires a selected PostgreSQL pool")
            }
            Self::MissingIdempotencyStore => {
                formatter.write_str("application extension requires a selected idempotency store")
            }
        }
    }
}

impl Error for ApplicationExtensionError {}

/// Cloneable handles to resources already constructed by [`SelectedRuntime`].
#[cfg(feature = "http")]
#[derive(Clone, Default)]
pub struct ApplicationRuntime {
    #[cfg(feature = "postgres")]
    postgres_pool: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    idempotency_store: Option<omnius_idempotency::PostgresIdempotencyStore>,
}

#[cfg(feature = "http")]
impl ApplicationRuntime {
    /// Returns the selected PostgreSQL pool without connecting or performing I/O.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationExtensionError::MissingPostgresPool`] when the
    /// selected runtime did not construct PostgreSQL.
    #[cfg(feature = "postgres")]
    pub fn postgres_pool(
        &self,
    ) -> Result<omnius_postgres::PostgresPool, ApplicationExtensionError> {
        self.postgres_pool
            .clone()
            .ok_or(ApplicationExtensionError::MissingPostgresPool)
    }

    /// Returns the configured idempotency store without connecting or performing I/O.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationExtensionError::MissingIdempotencyStore`] when the
    /// selected runtime did not construct idempotency.
    #[cfg(feature = "idempotency")]
    pub fn idempotency_store(
        &self,
    ) -> Result<omnius_idempotency::PostgresIdempotencyStore, ApplicationExtensionError> {
        self.idempotency_store
            .ok_or(ApplicationExtensionError::MissingIdempotencyStore)
    }
}

/// Application-owned HTTP routes and their complete public API contract.
#[cfg(feature = "http")]
pub struct ApplicationExtension {
    router: Router,
    routes: &'static [&'static str],
    openapi_document: serde_json::Value,
    operations: &'static [ExpectedOperation],
}

#[cfg(feature = "http")]
impl ApplicationExtension {
    /// Creates a complete application HTTP boundary.
    #[must_use]
    pub fn new(
        application_router: Router,
        route_ids: &'static [&'static str],
        openapi_document: serde_json::Value,
        operations: &'static [ExpectedOperation],
    ) -> Self {
        Self {
            router: application_router,
            routes: route_ids,
            openapi_document,
            operations,
        }
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

/// Resolves current administrative authority for an exact principal and action.
pub trait AdminAuthorityResolverPort: Send + Sync {
    /// Returns `true` only when current authority permits the action.
    fn authorizes(&self, principal: &str, action: &str) -> bool;
}

/// Executes one closed administrative operation.
pub trait AdminOperationHandlerPort: Send + Sync {
    /// Executes the named closed operation and reports whether it completed.
    fn execute(&self, operation: &str) -> bool;
}

/// Authenticates an application credential into a canonical subject.
pub trait AuthenticatedRuntimePort: Send + Sync {
    /// Returns the canonical subject only for a valid credential.
    fn authenticate(&self, credential: &str) -> Option<String>;
}

/// Revalidates one Redis-backed session.
pub trait RedisSessionRuntimePort: Send + Sync {
    /// Returns whether the session is live and current.
    fn session_is_live(&self, session_id: &str) -> bool;
}

/// Starts and completes an OIDC authorization flow.
pub trait OidcRuntimePort: Send + Sync {
    /// Returns whether the provider is configured for authorization.
    fn supports_provider(&self, provider: &str) -> bool;
}

/// Applies application OAuth authorization-server policy.
pub trait OauthRuntimePort: Send + Sync {
    /// Returns whether the client may request the exact scope.
    fn authorizes_client_scope(&self, client_id: &str, scope: &str) -> bool;
}

/// Executes `WebAuthn` registration and authentication ceremonies.
pub trait WebauthnRuntimePort: Send + Sync {
    /// Returns whether the relying party accepts this origin.
    fn accepts_origin(&self, origin: &str) -> bool;
}

/// Applies TOTP enrollment and verification policy.
pub trait TotpRuntimePort: Send + Sync {
    /// Verifies one code for the canonical subject.
    fn verifies_code(&self, subject: &str, code: &str) -> bool;
}

/// Dispatches typed jobs to application handlers.
pub trait JobsHandlersPort: Send + Sync {
    /// Returns whether a concrete handler accepts the stable job name.
    fn handles(&self, job_name: &str) -> bool;
}

/// Publishes one durable outbox event.
pub trait OutboxPublisherPort: Send + Sync {
    /// Publishes the canonical event and reports durable provider acceptance.
    fn publish(&self, event_id: &str, payload: &[u8]) -> bool;
}

/// Dispatches one durable inbox message.
pub trait InboxConsumersPort: Send + Sync {
    /// Consumes the named message and reports durable completion.
    fn consume(&self, message_name: &str, payload: &[u8]) -> bool;
}

/// Creates a fresh typed envelope for a scheduled occurrence.
pub trait SchedulerEnvelopeFactoryPort: Send + Sync {
    /// Builds canonical encoded envelope bytes for the occurrence.
    fn envelope(&self, schedule_id: &str, occurrence: u64) -> Option<Vec<u8>>;
}

/// Authorizes one realtime fan-out decision.
pub trait RealtimeFanoutAuthorizerPort: Send + Sync {
    /// Returns whether the subject may receive the exact topic.
    fn authorizes_fanout(&self, subject: &str, topic: &str) -> bool;
}

/// Revalidates realtime identity before delivery.
pub trait RealtimeIdentityRevalidatorPort: Send + Sync {
    /// Returns whether the subject is still live for this connection.
    fn identity_is_live(&self, subject: &str) -> bool;
}

/// Handles one canonical realtime event.
pub trait RealtimeEventHandlerPort: Send + Sync {
    /// Handles the named event and reports completion.
    fn handle_event(&self, event_name: &str, payload: &[u8]) -> bool;
}

/// Owns upload workflow state transitions.
pub trait UploadWorkflowPort: Send + Sync {
    /// Advances the upload and returns whether the transition committed.
    fn advance(&self, upload_id: &str, transition: &str) -> bool;
}

/// Authorizes one upload operation.
pub trait UploadAuthorizationPort: Send + Sync {
    /// Returns whether the subject may perform the operation.
    fn authorizes_upload(&self, subject: &str, upload_id: &str, operation: &str) -> bool;
}

/// Admits one durable Svix replay.
pub trait WebhooksSvixReplayAdmissionPort: Send + Sync {
    /// Returns whether the replay was durably admitted.
    fn admit_replay(&self, event_id: &str) -> bool;
}

/// Selects a verified inbound webhook provider adapter.
pub trait WebhooksInboundProviderAdaptersPort: Send + Sync {
    /// Returns whether a concrete adapter owns the provider ID.
    fn supports_provider(&self, provider: &str) -> bool;
}

/// Dispatches verified inbound webhook events.
pub trait WebhooksInboundHandlersPort: Send + Sync {
    /// Handles the verified provider event.
    fn handle_webhook(&self, provider: &str, event_id: &str, payload: &[u8]) -> bool;
}

/// Evaluates one feature flag using application-owned provider state.
pub trait FeatureFlagProviderPort: Send + Sync {
    /// Returns the provider decision for the subject.
    fn enabled(&self, flag: &str, subject: &str) -> bool;
}

/// Records one durable feature exposure.
pub trait FeatureFlagExposureRecorderPort: Send + Sync {
    /// Records the exposure and reports durable acceptance.
    fn record_exposure(&self, flag: &str, subject: &str, enabled: bool) -> bool;
}

/// Declares the stable application search schema.
pub trait SearchIndexSchemaPort: Send + Sync {
    /// Returns the immutable schema digest for an index.
    fn schema_digest(&self, index: &str) -> Option<String>;
}

/// Reauthorizes one search result against current source state.
pub trait SearchReauthorizerPort: Send + Sync {
    /// Returns whether the subject may still observe the source.
    fn reauthorize(&self, subject: &str, source_id: &str) -> bool;
}

/// Resolves an authoritative search projection.
pub trait SearchProjectionResolverPort: Send + Sync {
    /// Returns canonical projection bytes for the source.
    fn projection(&self, source_id: &str) -> Option<Vec<u8>>;
}

/// Executes one billing-provider operation.
pub trait BillingProviderPort: Send + Sync {
    /// Returns whether the provider durably accepted the operation.
    fn execute_billing(&self, account_id: &str, operation: &str) -> bool;
}

/// Supplies the closed application GraphQL schema.
pub trait GraphqlSchemaPort: Send + Sync {
    /// Returns whether the schema declares the field.
    fn declares_field(&self, field: &str) -> bool;
}

/// Injects canonical application request data into GraphQL execution.
pub trait GraphqlRequestDataInjectorPort: Send + Sync {
    /// Returns whether request data was attached for the subject.
    fn inject_request_data(&self, subject: &str) -> bool;
}

/// Executes one application gRPC method.
pub trait GrpcApplicationServicePort: Send + Sync {
    /// Executes the method and reports completion.
    fn execute_method(&self, method: &str, payload: &[u8]) -> bool;
}

/// Authenticates gRPC transport metadata.
pub trait GrpcAuthenticatorPort: Send + Sync {
    /// Returns the canonical subject for accepted authorization metadata.
    fn authenticate_metadata(&self, authorization: &str) -> Option<String>;
}

/// Authorizes one canonical gRPC method.
pub trait GrpcMethodPoliciesPort: Send + Sync {
    /// Returns whether the subject may call the method.
    fn authorizes_method(&self, subject: &str, method: &str) -> bool;
}

/// Supplies the immutable privacy inventory manifest.
pub trait PrivacyInventoryManifestPort: Send + Sync {
    /// Returns the immutable manifest digest.
    fn manifest_digest(&self) -> String;
}

/// Reads application-owned privacy inventory data.
pub trait PrivacyInventoryAdaptersPort: Send + Sync {
    /// Returns canonical inventory bytes for the data class.
    fn inventory(&self, data_class: &str) -> Option<Vec<u8>>;
}

/// Authorizes one privacy operation.
pub trait PrivacyAuthorizerPort: Send + Sync {
    /// Returns whether the subject may perform the operation.
    fn authorizes_privacy(&self, subject: &str, operation: &str) -> bool;
}

/// Executes one privacy lifecycle request.
pub trait PrivacyLifecycleHandlerPort: Send + Sync {
    /// Executes the request and reports durable completion.
    fn execute_lifecycle(&self, request_id: &str, operation: &str) -> bool;
}

/// Applies application consent policy.
pub trait PrivacyConsentPolicyPort: Send + Sync {
    /// Returns whether current consent covers the purpose.
    fn has_consent(&self, subject: &str, purpose: &str) -> bool;
}

/// Applies application moderation policy.
pub trait PrivacyModerationPolicyPort: Send + Sync {
    /// Returns whether bounded content passes moderation.
    fn permits_content(&self, subject: &str, content: &[u8]) -> bool;
}

/// Authorizes one LLM tool invocation.
pub trait LlmToolAuthorizationPort: Send + Sync {
    /// Returns whether the subject may invoke the tool.
    fn authorizes_tool(&self, subject: &str, tool: &str) -> bool;
}

/// Records one durable LLM tool audit outcome.
pub trait LlmToolAuditPort: Send + Sync {
    /// Records the terminal outcome and reports durable acceptance.
    fn record_tool_outcome(&self, invocation_id: &str, succeeded: bool) -> bool;
}

/// Scans one complete media object.
pub trait LlmMediaScannerPort: Send + Sync {
    /// Returns whether the complete object is clean.
    fn scans_clean(&self, media_id: &str, bytes: &[u8]) -> bool;
}

/// Authorizes one LLM media operation.
pub trait LlmMediaAuthorizationPort: Send + Sync {
    /// Returns whether the subject may perform the operation.
    fn authorizes_media(&self, subject: &str, media_id: &str, operation: &str) -> bool;
}

/// Stores and reads persistent LLM evaluation reports.
pub trait LlmEvaluationRepositoryPort: Send + Sync {
    /// Returns whether the evaluation report was durably stored.
    fn store_evaluation(&self, evaluation_id: &str, report: &[u8]) -> bool;
}

/// Resolves the canonical MCP capability registry.
pub trait McpCapabilityRegistryPort: Send + Sync {
    /// Returns whether the capability is currently declared.
    fn contains_capability(&self, capability: &str) -> bool;
}

/// Authenticates one MCP bearer credential.
pub trait McpBearerAuthenticatorPort: Send + Sync {
    /// Returns the canonical subject only for a valid credential.
    fn authenticate_bearer(&self, credential: &str) -> Option<String>;
}

/// Supplies the complete enterprise MCP trust boundary.
pub trait McpEnterprisePorts: Send + Sync {
    /// Returns whether live enterprise state authorizes the operation.
    fn authorizes_enterprise(&self, subject: &str, operation: &str) -> bool;
}

/// Stores MCP subscription state.
pub trait McpSubscriptionRepositoryPort: Send + Sync {
    /// Returns whether the subscription was durably stored.
    fn store_subscription(&self, subscription_id: &str) -> bool;
}

/// Authorizes MCP subscription operations.
pub trait McpSubscriptionAuthorizerPort: Send + Sync {
    /// Returns whether the subject may subscribe to the task.
    fn authorizes_subscription(&self, subject: &str, task_id: &str) -> bool;
}

/// Arms MCP subscription lifecycle callbacks.
pub trait McpSubscriptionRuntimePort: Send + Sync {
    /// Returns whether lifecycle handling was armed.
    fn arm_subscription(&self, subscription_id: &str) -> bool;
}

/// Delivers MCP subscription frames.
pub trait McpSubscriptionDeliveryPort: Send + Sync {
    /// Returns whether the frame was accepted for delivery.
    fn deliver_subscription(&self, subscription_id: &str, frame: &[u8]) -> bool;
}

/// Protects MCP task payloads.
pub trait McpTaskPayloadProtectorPort: Send + Sync {
    /// Seals a payload into authenticated bytes.
    fn seal_payload(&self, task_id: &str, payload: &[u8]) -> Option<Vec<u8>>;
}

/// Coordinates live MCP task cancellation.
pub trait McpCancellationRuntimePort: Send + Sync {
    /// Returns whether the active task generation was cancelled.
    fn cancel_task(&self, task_id: &str) -> bool;
}

/// Executes one MCP capability for a durable task.
pub trait McpCapabilityExecutorPort: Send + Sync {
    /// Executes the capability and reports completion.
    fn execute_capability(&self, capability: &str, payload: &[u8]) -> bool;
}

/// Supplies complete MCP Apps lifecycle, artifact, and messaging ports.
pub trait McpAppsPorts: Send + Sync {
    /// Returns whether the app action was durably admitted.
    fn admit_app_action(&self, app_id: &str, action: &str) -> bool;
}

#[cfg(any(
    feature = "admin",
    feature = "auth-password",
    feature = "auth-session-postgres",
    feature = "auth-session-redis",
    feature = "auth-oidc",
    feature = "auth-api-key",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "auth-oauth-server",
    feature = "billing",
    feature = "feature-flags",
    feature = "graphql",
    feature = "grpc",
    feature = "inbox",
    feature = "jobs-core",
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    feature = "mcp-apps",
    feature = "mcp-transport-http",
    feature = "mcp-server-core",
    feature = "mcp-auth-enterprise",
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    feature = "mcp-tasks",
    feature = "outbox",
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    feature = "scheduler",
    feature = "search-meilisearch",
    feature = "object-storage",
    feature = "webhooks-inbound",
    feature = "webhooks-svix",
    test
))]
macro_rules! port_setter {
    ($method:ident, $field:ident, $type:ty) => {
        #[doc = concat!("Supplies `", stringify!($field), "`.")]
        #[must_use]
        pub fn $method(mut self, port: Arc<$type>) -> Self {
            self.$field = Some(port);
            self
        }
    };
}

/// Complete application-owned administration contract.
#[derive(Default)]
#[cfg(any(feature = "admin", test))]
pub struct AdminRuntime {
    authority_resolver: Option<Arc<dyn AdminAuthorityResolverPort>>,
    operation_handler: Option<Arc<dyn AdminOperationHandlerPort>>,
}
#[cfg(any(feature = "admin", test))]
impl AdminRuntime {
    port_setter!(
        with_authority_resolver,
        authority_resolver,
        dyn AdminAuthorityResolverPort
    );
    port_setter!(
        with_operation_handler,
        operation_handler,
        dyn AdminOperationHandlerPort
    );
}

/// Complete application-owned authentication contract.
#[derive(Default)]
#[cfg(any(
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
pub struct AuthRuntime {
    #[cfg(any(
        feature = "auth-password",
        feature = "auth-session-postgres",
        feature = "auth-api-key",
        test
    ))]
    authenticated: Option<Arc<dyn AuthenticatedRuntimePort>>,
    #[cfg(any(feature = "auth-session-redis", test))]
    redis_session: Option<Arc<dyn RedisSessionRuntimePort>>,
    #[cfg(any(feature = "auth-oidc", test))]
    oidc: Option<Arc<dyn OidcRuntimePort>>,
    #[cfg(any(feature = "auth-oauth-server", test))]
    oauth: Option<Arc<dyn OauthRuntimePort>>,
    #[cfg(any(feature = "auth-webauthn", test))]
    webauthn: Option<Arc<dyn WebauthnRuntimePort>>,
    #[cfg(any(feature = "auth-totp", test))]
    totp: Option<Arc<dyn TotpRuntimePort>>,
}
#[cfg(any(
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
impl AuthRuntime {
    #[cfg(any(
        feature = "auth-password",
        feature = "auth-session-postgres",
        feature = "auth-api-key",
        test
    ))]
    port_setter!(
        with_authenticated_runtime,
        authenticated,
        dyn AuthenticatedRuntimePort
    );
    #[cfg(any(feature = "auth-session-redis", test))]
    port_setter!(
        with_redis_session_runtime,
        redis_session,
        dyn RedisSessionRuntimePort
    );
    #[cfg(any(feature = "auth-oidc", test))]
    port_setter!(with_oidc_runtime, oidc, dyn OidcRuntimePort);
    #[cfg(any(feature = "auth-oauth-server", test))]
    port_setter!(with_oauth_runtime, oauth, dyn OauthRuntimePort);
    #[cfg(any(feature = "auth-webauthn", test))]
    port_setter!(with_webauthn_runtime, webauthn, dyn WebauthnRuntimePort);
    #[cfg(any(feature = "auth-totp", test))]
    port_setter!(with_totp_runtime, totp, dyn TotpRuntimePort);
}

/// Application-owned billing contract.
#[derive(Default)]
#[cfg(any(feature = "billing", test))]
pub struct BillingRuntime {
    provider: Option<Arc<dyn BillingProviderPort>>,
}
#[cfg(any(feature = "billing", test))]
impl BillingRuntime {
    port_setter!(with_provider, provider, dyn BillingProviderPort);
}

/// Application-owned feature-flag contract.
#[derive(Default)]
#[cfg(any(feature = "feature-flags", test))]
pub struct FeatureFlagsRuntime {
    provider: Option<Arc<dyn FeatureFlagProviderPort>>,
    exposure_recorder: Option<Arc<dyn FeatureFlagExposureRecorderPort>>,
}
#[cfg(any(feature = "feature-flags", test))]
impl FeatureFlagsRuntime {
    port_setter!(with_provider, provider, dyn FeatureFlagProviderPort);
    port_setter!(
        with_exposure_recorder,
        exposure_recorder,
        dyn FeatureFlagExposureRecorderPort
    );
}

/// Application-owned GraphQL contract.
#[derive(Default)]
#[cfg(any(feature = "graphql", test))]
pub struct GraphqlRuntime {
    schema: Option<Arc<dyn GraphqlSchemaPort>>,
    request_data_injector: Option<Arc<dyn GraphqlRequestDataInjectorPort>>,
}
#[cfg(any(feature = "graphql", test))]
impl GraphqlRuntime {
    port_setter!(with_schema, schema, dyn GraphqlSchemaPort);
    port_setter!(
        with_request_data_injector,
        request_data_injector,
        dyn GraphqlRequestDataInjectorPort
    );
}

/// Application-owned gRPC contract.
#[derive(Default)]
#[cfg(any(feature = "grpc", test))]
pub struct GrpcRuntime {
    application_service: Option<Arc<dyn GrpcApplicationServicePort>>,
    authenticator: Option<Arc<dyn GrpcAuthenticatorPort>>,
    method_policies: Option<Arc<dyn GrpcMethodPoliciesPort>>,
}
#[cfg(any(feature = "grpc", test))]
impl GrpcRuntime {
    port_setter!(
        with_application_service,
        application_service,
        dyn GrpcApplicationServicePort
    );
    port_setter!(with_authenticator, authenticator, dyn GrpcAuthenticatorPort);
    port_setter!(
        with_method_policies,
        method_policies,
        dyn GrpcMethodPoliciesPort
    );
}

/// Application-owned jobs contract.
#[derive(Default)]
#[cfg(any(feature = "jobs-core", test))]
pub struct JobsRuntime {
    handlers: Option<Arc<dyn JobsHandlersPort>>,
}
#[cfg(any(feature = "jobs-core", test))]
impl JobsRuntime {
    port_setter!(with_handlers, handlers, dyn JobsHandlersPort);
}

/// Application-owned durable inbox contract.
#[derive(Default)]
#[cfg(any(feature = "inbox", test))]
pub struct InboxRuntime {
    consumers: Option<Arc<dyn InboxConsumersPort>>,
}
#[cfg(any(feature = "inbox", test))]
impl InboxRuntime {
    port_setter!(with_consumers, consumers, dyn InboxConsumersPort);
}

/// Application-owned outbox contract.
#[derive(Default)]
#[cfg(any(feature = "outbox", test))]
pub struct OutboxRuntime {
    publisher: Option<Arc<dyn OutboxPublisherPort>>,
}
#[cfg(any(feature = "outbox", test))]
impl OutboxRuntime {
    port_setter!(with_publisher, publisher, dyn OutboxPublisherPort);
}

/// Application-owned scheduler contract.
#[derive(Default)]
#[cfg(any(feature = "scheduler", test))]
pub struct SchedulerRuntime {
    envelope_factory: Option<Arc<dyn SchedulerEnvelopeFactoryPort>>,
}
#[cfg(any(feature = "scheduler", test))]
impl SchedulerRuntime {
    port_setter!(
        with_envelope_factory,
        envelope_factory,
        dyn SchedulerEnvelopeFactoryPort
    );
}

/// Application-owned realtime contract.
#[derive(Default)]
#[cfg(any(
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    test
))]
pub struct RealtimeRuntime {
    #[cfg(any(feature = "realtime-core", test))]
    fanout_authorizer: Option<Arc<dyn RealtimeFanoutAuthorizerPort>>,
    #[cfg(any(feature = "realtime-core", test))]
    identity_revalidator: Option<Arc<dyn RealtimeIdentityRevalidatorPort>>,
    #[cfg(any(
        feature = "redis-core",
        feature = "events-nats",
        feature = "realtime-core",
        test
    ))]
    event_handler: Option<Arc<dyn RealtimeEventHandlerPort>>,
}
#[cfg(any(
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    test
))]
impl RealtimeRuntime {
    #[cfg(any(feature = "realtime-core", test))]
    port_setter!(
        with_fanout_authorizer,
        fanout_authorizer,
        dyn RealtimeFanoutAuthorizerPort
    );
    #[cfg(any(feature = "realtime-core", test))]
    port_setter!(
        with_identity_revalidator,
        identity_revalidator,
        dyn RealtimeIdentityRevalidatorPort
    );
    #[cfg(any(
        feature = "redis-core",
        feature = "events-nats",
        feature = "realtime-core",
        test
    ))]
    port_setter!(
        with_event_handler,
        event_handler,
        dyn RealtimeEventHandlerPort
    );
}

/// Application-owned upload contract.
#[derive(Default)]
#[cfg(any(feature = "object-storage", test))]
pub struct UploadsRuntime {
    workflow: Option<Arc<dyn UploadWorkflowPort>>,
    authorization: Option<Arc<dyn UploadAuthorizationPort>>,
}
#[cfg(any(feature = "object-storage", test))]
impl UploadsRuntime {
    port_setter!(with_workflow, workflow, dyn UploadWorkflowPort);
    port_setter!(
        with_authorization,
        authorization,
        dyn UploadAuthorizationPort
    );
}

/// Application-owned inbound-webhook contract.
#[derive(Default)]
#[cfg(any(feature = "webhooks-inbound", test))]
pub struct WebhooksInboundRuntime {
    provider_adapters: Option<Arc<dyn WebhooksInboundProviderAdaptersPort>>,
    handlers: Option<Arc<dyn WebhooksInboundHandlersPort>>,
}
#[cfg(any(feature = "webhooks-inbound", test))]
impl WebhooksInboundRuntime {
    port_setter!(
        with_provider_adapters,
        provider_adapters,
        dyn WebhooksInboundProviderAdaptersPort
    );
    port_setter!(with_handlers, handlers, dyn WebhooksInboundHandlersPort);
}

/// Application-owned Svix webhook contract.
#[derive(Default)]
#[cfg(any(feature = "webhooks-svix", test))]
pub struct WebhooksSvixRuntime {
    replay_admission: Option<Arc<dyn WebhooksSvixReplayAdmissionPort>>,
}
#[cfg(any(feature = "webhooks-svix", test))]
impl WebhooksSvixRuntime {
    port_setter!(
        with_replay_admission,
        replay_admission,
        dyn WebhooksSvixReplayAdmissionPort
    );
}

/// Application-owned search contract.
#[derive(Default)]
#[cfg(any(feature = "search-meilisearch", test))]
pub struct SearchRuntime {
    index_schema: Option<Arc<dyn SearchIndexSchemaPort>>,
    reauthorizer: Option<Arc<dyn SearchReauthorizerPort>>,
    projection_resolver: Option<Arc<dyn SearchProjectionResolverPort>>,
}
#[cfg(any(feature = "search-meilisearch", test))]
impl SearchRuntime {
    port_setter!(with_index_schema, index_schema, dyn SearchIndexSchemaPort);
    port_setter!(with_reauthorizer, reauthorizer, dyn SearchReauthorizerPort);
    port_setter!(
        with_projection_resolver,
        projection_resolver,
        dyn SearchProjectionResolverPort
    );
}

/// Application-owned privacy contract.
#[derive(Default)]
#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
pub struct PrivacyRuntime {
    #[cfg(any(feature = "data-lifecycle", test))]
    inventory_manifest: Option<Arc<dyn PrivacyInventoryManifestPort>>,
    #[cfg(any(feature = "data-lifecycle", test))]
    inventory_adapters: Option<Arc<dyn PrivacyInventoryAdaptersPort>>,
    #[cfg(any(feature = "data-lifecycle", test))]
    authorizer: Option<Arc<dyn PrivacyAuthorizerPort>>,
    #[cfg(any(feature = "data-lifecycle", test))]
    lifecycle_handler: Option<Arc<dyn PrivacyLifecycleHandlerPort>>,
    #[cfg(any(feature = "consent", test))]
    consent_policy: Option<Arc<dyn PrivacyConsentPolicyPort>>,
    #[cfg(any(feature = "moderation", test))]
    moderation_policy: Option<Arc<dyn PrivacyModerationPolicyPort>>,
}
#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
impl PrivacyRuntime {
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(
        with_inventory_manifest,
        inventory_manifest,
        dyn PrivacyInventoryManifestPort
    );
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(
        with_inventory_adapters,
        inventory_adapters,
        dyn PrivacyInventoryAdaptersPort
    );
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(with_authorizer, authorizer, dyn PrivacyAuthorizerPort);
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(
        with_lifecycle_handler,
        lifecycle_handler,
        dyn PrivacyLifecycleHandlerPort
    );
    #[cfg(any(feature = "consent", test))]
    port_setter!(
        with_consent_policy,
        consent_policy,
        dyn PrivacyConsentPolicyPort
    );
    #[cfg(any(feature = "moderation", test))]
    port_setter!(
        with_moderation_policy,
        moderation_policy,
        dyn PrivacyModerationPolicyPort
    );
}

/// Application-owned LLM contract.
#[derive(Default)]
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
pub struct LlmRuntime {
    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-tool-runtime",
        feature = "llm-http-api",
        test
    ))]
    tool_authorization: Option<Arc<dyn LlmToolAuthorizationPort>>,
    #[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
    tool_audit: Option<Arc<dyn LlmToolAuditPort>>,
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    media_scanner: Option<Arc<dyn LlmMediaScannerPort>>,
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    media_authorization: Option<Arc<dyn LlmMediaAuthorizationPort>>,
    #[cfg(test)]
    evaluation_repository: Option<Arc<dyn LlmEvaluationRepositoryPort>>,
}
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
impl LlmRuntime {
    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-tool-runtime",
        feature = "llm-http-api",
        test
    ))]
    port_setter!(
        with_tool_authorization,
        tool_authorization,
        dyn LlmToolAuthorizationPort
    );
    #[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
    port_setter!(with_tool_audit, tool_audit, dyn LlmToolAuditPort);
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    port_setter!(with_media_scanner, media_scanner, dyn LlmMediaScannerPort);
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    port_setter!(
        with_media_authorization,
        media_authorization,
        dyn LlmMediaAuthorizationPort
    );
    #[cfg(test)]
    port_setter!(
        with_evaluation_repository,
        evaluation_repository,
        dyn LlmEvaluationRepositoryPort
    );
}

/// Application-owned MCP core contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-server-core", test))]
pub struct McpCoreRuntime {
    capability_registry: Option<Arc<dyn McpCapabilityRegistryPort>>,
}
#[cfg(any(feature = "mcp-server-core", test))]
impl McpCoreRuntime {
    port_setter!(
        with_capability_registry,
        capability_registry,
        dyn McpCapabilityRegistryPort
    );
}

/// Application-owned MCP authentication contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-transport-http", test))]
pub struct McpAuthRuntime {
    bearer_authenticator: Option<Arc<dyn McpBearerAuthenticatorPort>>,
}
#[cfg(any(feature = "mcp-transport-http", test))]
impl McpAuthRuntime {
    port_setter!(
        with_bearer_authenticator,
        bearer_authenticator,
        dyn McpBearerAuthenticatorPort
    );
}

/// Application-owned MCP enterprise contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-auth-enterprise", test))]
pub struct McpEnterpriseRuntime {
    ports: Option<Arc<dyn McpEnterprisePorts>>,
}
#[cfg(any(feature = "mcp-auth-enterprise", test))]
impl McpEnterpriseRuntime {
    port_setter!(with_ports, ports, dyn McpEnterprisePorts);
}

/// Application-owned MCP subscription contract.
#[derive(Default)]
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
pub struct McpSubscriptionsRuntime {
    repository: Option<Arc<dyn McpSubscriptionRepositoryPort>>,
    authorizer: Option<Arc<dyn McpSubscriptionAuthorizerPort>>,
    runtime: Option<Arc<dyn McpSubscriptionRuntimePort>>,
    delivery: Option<Arc<dyn McpSubscriptionDeliveryPort>>,
}
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
impl McpSubscriptionsRuntime {
    port_setter!(
        with_repository,
        repository,
        dyn McpSubscriptionRepositoryPort
    );
    port_setter!(
        with_authorizer,
        authorizer,
        dyn McpSubscriptionAuthorizerPort
    );
    port_setter!(with_runtime, runtime, dyn McpSubscriptionRuntimePort);
    port_setter!(with_delivery, delivery, dyn McpSubscriptionDeliveryPort);
}

/// Application-owned durable MCP task contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-tasks", test))]
pub struct McpTasksRuntime {
    payload_protector: Option<Arc<dyn McpTaskPayloadProtectorPort>>,
    cancellation_runtime: Option<Arc<dyn McpCancellationRuntimePort>>,
    capability_executor: Option<Arc<dyn McpCapabilityExecutorPort>>,
}
#[cfg(any(feature = "mcp-tasks", test))]
impl McpTasksRuntime {
    port_setter!(
        with_payload_protector,
        payload_protector,
        dyn McpTaskPayloadProtectorPort
    );
    port_setter!(
        with_cancellation_runtime,
        cancellation_runtime,
        dyn McpCancellationRuntimePort
    );
    port_setter!(
        with_capability_executor,
        capability_executor,
        dyn McpCapabilityExecutorPort
    );
}

/// Application-owned MCP Apps contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-apps", test))]
pub struct McpAppsRuntime {
    ports: Option<Arc<dyn McpAppsPorts>>,
}
#[cfg(any(feature = "mcp-apps", test))]
impl McpAppsRuntime {
    port_setter!(with_ports, ports, dyn McpAppsPorts);
}

/// Validated static-delivery runtime.
#[cfg(feature = "web-static")]
pub struct WebStaticRuntime {
    router: Router,
}
#[cfg(feature = "web-static")]
impl WebStaticRuntime {
    /// Creates a runtime from the validated delivery router.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self { router }
    }
}

/// Connected Redis/Apalis worker outputs.
#[cfg(feature = "jobs-apalis-redis")]
pub struct JobsApalisRedisRuntime {
    readiness: HealthCheckSpec,
    worker: TaskSpec,
}
#[cfg(feature = "jobs-apalis-redis")]
impl JobsApalisRedisRuntime {
    /// Creates provider outputs after a typed handler is bound.
    #[must_use]
    pub fn new(readiness: HealthCheckSpec, worker: TaskSpec) -> Self {
        Self { readiness, worker }
    }
}

/// Verified PGMQ worker outputs.
#[cfg(feature = "jobs-pgmq")]
pub struct JobsPgmqRuntime {
    readiness: HealthCheckSpec,
    worker: TaskSpec,
}
#[cfg(feature = "jobs-pgmq")]
impl JobsPgmqRuntime {
    /// Creates provider outputs after a typed handler is bound.
    #[must_use]
    pub fn new(readiness: HealthCheckSpec, worker: TaskSpec) -> Self {
        Self { readiness, worker }
    }
}

/// Runtime output for one optional router.
#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api",
))]
pub struct RouterRuntime {
    router: Router,
}
#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api",
))]
impl RouterRuntime {
    /// Creates a named module router output.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self { router }
    }
}

/// Runtime output for one supervised task.
#[cfg(any(
    feature = "outbox",
    feature = "scheduler",
    feature = "events-redis-ephemeral",
    feature = "notifications",
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    feature = "mcp-tasks",
    feature = "llm-tool-runtime",
    feature = "llm-media",
))]
pub struct TaskRuntime {
    task: TaskSpec,
}
#[cfg(any(
    feature = "outbox",
    feature = "scheduler",
    feature = "events-redis-ephemeral",
    feature = "notifications",
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    feature = "mcp-tasks",
    feature = "llm-tool-runtime",
    feature = "llm-media",
))]
impl TaskRuntime {
    /// Creates a named module task output.
    #[must_use]
    pub fn new(task: TaskSpec) -> Self {
        Self { task }
    }
}

/// Runtime output for one health check.
#[cfg(any(
    feature = "object-storage",
    feature = "email",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing",
))]
pub struct HealthRuntime {
    health: HealthCheckSpec,
}
#[cfg(any(
    feature = "object-storage",
    feature = "email",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing",
))]
impl HealthRuntime {
    /// Creates a named module health output.
    #[must_use]
    pub fn new(health: HealthCheckSpec) -> Self {
        Self { health }
    }
}

/// Runtime outputs for a task-backed provider with readiness.
#[cfg(feature = "events-nats")]
pub struct TaskHealthRuntime {
    task: TaskSpec,
    health: HealthCheckSpec,
}
#[cfg(feature = "events-nats")]
impl TaskHealthRuntime {
    /// Creates task and health outputs.
    #[must_use]
    pub fn new(task: TaskSpec, health: HealthCheckSpec) -> Self {
        Self { task, health }
    }
}

/// Runtime outputs for a routed background processor.
#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
pub struct RouterTaskRuntime {
    router: Router,
    task: TaskSpec,
}
#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
impl RouterTaskRuntime {
    /// Creates router and task outputs.
    #[must_use]
    pub fn new(router: Router, task: TaskSpec) -> Self {
        Self { router, task }
    }
}

/// Runtime outputs for an authenticated router with readiness.
#[cfg(feature = "mcp-transport-http")]
pub struct RouterHealthRuntime {
    router: Router,
    health: HealthCheckSpec,
}
#[cfg(feature = "mcp-transport-http")]
impl RouterHealthRuntime {
    /// Creates router and health outputs.
    #[must_use]
    pub fn new(router: Router, health: HealthCheckSpec) -> Self {
        Self { router, health }
    }
}

macro_rules! runtime_setter {
    ($condition:meta; $method:ident, $field:ident, $type:ty) => {
        #[cfg($condition)]
        #[doc = concat!("Supplies the named `", stringify!($field), "` runtime.")]
        #[must_use]
        pub fn $method(mut self, runtime: $type) -> Self {
            self.$field = Some(runtime);
            self
        }
    };
}

#[cfg(feature = "http")]
type ApplicationExtensionFactory = Box<
    dyn FnOnce(ApplicationRuntime) -> Result<ApplicationExtension, ApplicationExtensionError>
        + Send
        + 'static,
>;

/// Application-owned typed domain ports and their validated runtime outputs.
///
/// Port families are separate from module outputs: a router, task, health
/// check, or `OpenAPI` fragment never proves that an application policy exists.
#[derive(Default)]
pub struct ApplicationContributions {
    #[cfg(feature = "rate-limit-local")]
    application_rate_limit: Option<ApplicationRateLimitConfig>,
    #[cfg(feature = "http")]
    application_extension_factory: Option<ApplicationExtensionFactory>,
    #[cfg(feature = "http")]
    application_extension: Option<ApplicationExtension>,
    #[cfg(feature = "postgres")]
    postgres_pool: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    idempotency_store: Option<omnius_idempotency::PostgresIdempotencyStore>,
    #[cfg(feature = "openapi")]
    openapi_config: Option<omnius_openapi::OpenApiConfig>,
    #[cfg(feature = "outbound-http")]
    outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
    #[cfg(any(feature = "admin", test))]
    admin: Option<AdminRuntime>,
    #[cfg(any(
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
    auth: Option<AuthRuntime>,
    #[cfg(any(feature = "billing", test))]
    billing: Option<BillingRuntime>,
    #[cfg(any(feature = "feature-flags", test))]
    feature_flags: Option<FeatureFlagsRuntime>,
    #[cfg(any(feature = "graphql", test))]
    graphql: Option<GraphqlRuntime>,
    #[cfg(any(feature = "grpc", test))]
    grpc: Option<GrpcRuntime>,
    #[cfg(any(feature = "inbox", test))]
    inbox: Option<InboxRuntime>,
    #[cfg(any(feature = "jobs-core", test))]
    jobs: Option<JobsRuntime>,
    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        test
    ))]
    llm: Option<LlmRuntime>,
    #[cfg(any(feature = "mcp-apps", test))]
    mcp_apps: Option<McpAppsRuntime>,
    #[cfg(any(feature = "mcp-transport-http", test))]
    mcp_auth: Option<McpAuthRuntime>,
    #[cfg(any(feature = "mcp-server-core", test))]
    mcp_core: Option<McpCoreRuntime>,
    #[cfg(any(feature = "mcp-auth-enterprise", test))]
    mcp_enterprise: Option<McpEnterpriseRuntime>,
    #[cfg(any(
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        test
    ))]
    mcp_subscriptions: Option<McpSubscriptionsRuntime>,
    #[cfg(any(feature = "mcp-tasks", test))]
    mcp_tasks: Option<McpTasksRuntime>,
    #[cfg(any(feature = "outbox", test))]
    outbox: Option<OutboxRuntime>,
    #[cfg(any(
        feature = "data-lifecycle",
        feature = "consent",
        feature = "moderation",
        test
    ))]
    privacy: Option<PrivacyRuntime>,
    #[cfg(any(
        feature = "redis-core",
        feature = "events-nats",
        feature = "realtime-core",
        test
    ))]
    realtime: Option<RealtimeRuntime>,
    #[cfg(any(feature = "scheduler", test))]
    scheduler: Option<SchedulerRuntime>,
    #[cfg(any(feature = "search-meilisearch", test))]
    search: Option<SearchRuntime>,
    #[cfg(any(feature = "object-storage", test))]
    uploads: Option<UploadsRuntime>,
    #[cfg(any(feature = "webhooks-inbound", test))]
    webhooks_inbound: Option<WebhooksInboundRuntime>,
    #[cfg(any(feature = "webhooks-svix", test))]
    webhooks_svix: Option<WebhooksSvixRuntime>,
    #[cfg(feature = "web-static")]
    web_static_output: Option<WebStaticRuntime>,
    #[cfg(feature = "jobs-apalis-redis")]
    jobs_apalis_redis_output: Option<JobsApalisRedisRuntime>,
    #[cfg(feature = "jobs-pgmq")]
    jobs_pgmq_output: Option<JobsPgmqRuntime>,
    #[cfg(feature = "outbox")]
    outbox_output: Option<TaskRuntime>,
    #[cfg(feature = "scheduler")]
    scheduler_output: Option<TaskRuntime>,
    #[cfg(feature = "events-nats")]
    events_nats_output: Option<TaskHealthRuntime>,
    #[cfg(feature = "events-redis-ephemeral")]
    events_redis_output: Option<TaskRuntime>,
    #[cfg(feature = "sse")]
    sse_output: Option<RouterRuntime>,
    #[cfg(feature = "websockets")]
    websockets_output: Option<RouterRuntime>,
    #[cfg(feature = "object-storage")]
    object_storage_output: Option<HealthRuntime>,
    #[cfg(feature = "email")]
    email_output: Option<HealthRuntime>,
    #[cfg(feature = "notifications")]
    notifications_output: Option<TaskRuntime>,
    #[cfg(feature = "webhooks-svix")]
    webhooks_svix_output: Option<HealthRuntime>,
    #[cfg(feature = "webhooks-inbound")]
    webhooks_inbound_output: Option<RouterTaskRuntime>,
    #[cfg(feature = "auth-oidc")]
    auth_oidc_output: Option<RouterTaskRuntime>,
    #[cfg(feature = "auth-webauthn")]
    auth_webauthn_output: Option<RouterRuntime>,
    #[cfg(feature = "auth-totp")]
    auth_totp_output: Option<RouterRuntime>,
    #[cfg(feature = "mcp-transport-http")]
    mcp_http_output: Option<RouterHealthRuntime>,
    #[cfg(feature = "mcp-auth-oauth")]
    mcp_auth_oauth_output: Option<RouterRuntime>,
    #[cfg(feature = "mcp-subscriptions-local")]
    mcp_subscriptions_local_output: Option<TaskRuntime>,
    #[cfg(feature = "mcp-subscriptions-redis")]
    mcp_subscriptions_redis_output: Option<TaskRuntime>,
    #[cfg(feature = "mcp-subscriptions-nats")]
    mcp_subscriptions_nats_output: Option<TaskRuntime>,
    #[cfg(feature = "mcp-tasks")]
    mcp_tasks_output: Option<TaskRuntime>,
    #[cfg(feature = "llm-provider-rig")]
    llm_provider_rig_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-provider-bedrock")]
    llm_provider_bedrock_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-provider-vertex")]
    llm_provider_vertex_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-routing")]
    llm_routing_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-tool-runtime")]
    llm_tool_runtime_output: Option<TaskRuntime>,
    #[cfg(feature = "llm-media")]
    llm_media_output: Option<TaskRuntime>,
    #[cfg(feature = "llm-http-api")]
    llm_http_api_output: Option<RouterRuntime>,
}

impl ApplicationContributions {
    /// Creates an empty, fail-closed contribution set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies the application-wide local rate-limit policy.
    #[cfg(feature = "rate-limit-local")]
    #[must_use]
    pub fn with_application_rate_limit(
        mut self,
        application_rate_limit: ApplicationRateLimitConfig,
    ) -> Self {
        self.application_rate_limit = Some(application_rate_limit);
        self
    }

    /// Preserves the generated application API when local limiting is not selected.
    #[cfg(not(feature = "rate-limit-local"))]
    #[must_use]
    pub fn with_application_rate_limit(
        self,
        _application_rate_limit: ApplicationRateLimitConfig,
    ) -> Self {
        self
    }

    /// Defers application extension construction until selected resources exist.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn with_application_extension<F>(mut self, factory: F) -> Self
    where
        F: FnOnce(ApplicationRuntime) -> Result<ApplicationExtension, ApplicationExtensionError>
            + Send
            + 'static,
    {
        self.application_extension_factory = Some(Box::new(factory));
        self
    }

    /// Supplies resources constructed from feature-gated selected configuration.
    ///
    /// The application extension factory, when present, is consumed only after
    /// these selected resources have been made available.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationExtensionError`] when the one-shot application
    /// extension factory cannot construct its runtime.
    #[cfg(any(feature = "http", feature = "postgres", feature = "outbound-http"))]
    pub fn with_selected_runtime(
        mut self,
        #[cfg(any(feature = "postgres", feature = "openapi", feature = "outbound-http"))]
        runtime: SelectedRuntime,
        #[cfg(not(any(feature = "postgres", feature = "openapi", feature = "outbound-http")))]
        _runtime: SelectedRuntime,
    ) -> Result<Self, ApplicationExtensionError> {
        #[cfg(feature = "http")]
        let application_runtime = ApplicationRuntime {
            #[cfg(feature = "postgres")]
            postgres_pool: runtime.postgres.clone(),
            #[cfg(feature = "idempotency")]
            idempotency_store: runtime.idempotency_store,
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
        if let Some(factory) = self.application_extension_factory.take() {
            self.application_extension = Some(factory(application_runtime)?);
        }
        Ok(self)
    }

    #[cfg(not(any(feature = "http", feature = "postgres", feature = "outbound-http")))]
    /// Returns the unchanged contribution set when no provider resource feature is selected.
    pub fn with_selected_runtime(
        self,
        _runtime: SelectedRuntime,
    ) -> Result<Self, ApplicationExtensionError> {
        Ok(self)
    }

    runtime_setter!(any(feature = "admin", test); with_admin_runtime, admin, AdminRuntime);
    runtime_setter!(
        any(
            feature = "auth-password",
            feature = "auth-session-postgres",
            feature = "auth-session-redis",
            feature = "auth-oidc",
            feature = "auth-api-key",
            feature = "auth-webauthn",
            feature = "auth-totp",
            feature = "auth-oauth-server",
            test
        );
        with_auth_runtime,
        auth,
        AuthRuntime
    );
    runtime_setter!(any(feature = "billing", test); with_billing_runtime, billing, BillingRuntime);
    runtime_setter!(
        any(feature = "feature-flags", test);
        with_feature_flags_runtime,
        feature_flags,
        FeatureFlagsRuntime
    );
    runtime_setter!(any(feature = "graphql", test); with_graphql_runtime, graphql, GraphqlRuntime);
    runtime_setter!(any(feature = "grpc", test); with_grpc_runtime, grpc, GrpcRuntime);
    runtime_setter!(any(feature = "inbox", test); with_inbox_runtime, inbox, InboxRuntime);
    runtime_setter!(any(feature = "jobs-core", test); with_jobs_runtime, jobs, JobsRuntime);
    runtime_setter!(
        any(
            feature = "llm-provider-rig",
            feature = "llm-tool-runtime",
            feature = "llm-media",
            test
        );
        with_llm_runtime,
        llm,
        LlmRuntime
    );
    runtime_setter!(any(feature = "mcp-apps", test); with_mcp_apps_runtime, mcp_apps, McpAppsRuntime);
    runtime_setter!(
        any(feature = "mcp-transport-http", test);
        with_mcp_auth_runtime,
        mcp_auth,
        McpAuthRuntime
    );
    runtime_setter!(
        any(feature = "mcp-server-core", test);
        with_mcp_core_runtime,
        mcp_core,
        McpCoreRuntime
    );
    runtime_setter!(
        any(feature = "mcp-auth-enterprise", test);
        with_mcp_enterprise_runtime,
        mcp_enterprise,
        McpEnterpriseRuntime
    );
    runtime_setter!(
        any(
            feature = "mcp-subscriptions-local",
            feature = "mcp-subscriptions-redis",
            feature = "mcp-subscriptions-nats",
            test
        );
        with_mcp_subscriptions_runtime,
        mcp_subscriptions,
        McpSubscriptionsRuntime
    );
    runtime_setter!(any(feature = "mcp-tasks", test); with_mcp_tasks_runtime, mcp_tasks, McpTasksRuntime);
    runtime_setter!(any(feature = "outbox", test); with_outbox_runtime, outbox, OutboxRuntime);
    runtime_setter!(
        any(
            feature = "data-lifecycle",
            feature = "consent",
            feature = "moderation",
            test
        );
        with_privacy_runtime,
        privacy,
        PrivacyRuntime
    );
    runtime_setter!(
        any(
            feature = "redis-core",
            feature = "events-nats",
            feature = "realtime-core",
            test
        );
        with_realtime_runtime,
        realtime,
        RealtimeRuntime
    );
    runtime_setter!(any(feature = "scheduler", test); with_scheduler_runtime, scheduler, SchedulerRuntime);
    runtime_setter!(
        any(feature = "search-meilisearch", test);
        with_search_runtime,
        search,
        SearchRuntime
    );
    runtime_setter!(
        any(feature = "object-storage", test);
        with_uploads_runtime,
        uploads,
        UploadsRuntime
    );
    runtime_setter!(
        any(feature = "webhooks-inbound", test);
        with_webhooks_inbound_runtime,
        webhooks_inbound,
        WebhooksInboundRuntime
    );
    runtime_setter!(
        any(feature = "webhooks-svix", test);
        with_webhooks_svix_runtime,
        webhooks_svix,
        WebhooksSvixRuntime
    );

    runtime_setter!(
        feature = "web-static";
        with_web_static,
        web_static_output,
        WebStaticRuntime
    );
    runtime_setter!(
        feature = "jobs-apalis-redis";
        with_jobs_apalis_redis,
        jobs_apalis_redis_output,
        JobsApalisRedisRuntime
    );
    runtime_setter!(
        feature = "jobs-pgmq";
        with_jobs_pgmq,
        jobs_pgmq_output,
        JobsPgmqRuntime
    );
    runtime_setter!(feature = "outbox"; with_outbox_output, outbox_output, TaskRuntime);
    runtime_setter!(feature = "scheduler"; with_scheduler_output, scheduler_output, TaskRuntime);
    runtime_setter!(
        feature = "events-nats";
        with_events_nats_output,
        events_nats_output,
        TaskHealthRuntime
    );
    runtime_setter!(
        feature = "events-redis-ephemeral";
        with_events_redis_output,
        events_redis_output,
        TaskRuntime
    );
    runtime_setter!(feature = "sse"; with_sse_output, sse_output, RouterRuntime);
    runtime_setter!(
        feature = "websockets";
        with_websockets_output,
        websockets_output,
        RouterRuntime
    );
    runtime_setter!(
        feature = "object-storage";
        with_object_storage_output,
        object_storage_output,
        HealthRuntime
    );
    runtime_setter!(feature = "email"; with_email_output, email_output, HealthRuntime);
    runtime_setter!(
        feature = "notifications";
        with_notifications_output,
        notifications_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "webhooks-svix";
        with_webhooks_svix_output,
        webhooks_svix_output,
        HealthRuntime
    );
    runtime_setter!(
        feature = "webhooks-inbound";
        with_webhooks_inbound_output,
        webhooks_inbound_output,
        RouterTaskRuntime
    );
    runtime_setter!(
        feature = "auth-oidc";
        with_auth_oidc_output,
        auth_oidc_output,
        RouterTaskRuntime
    );
    runtime_setter!(
        feature = "auth-webauthn";
        with_auth_webauthn_output,
        auth_webauthn_output,
        RouterRuntime
    );
    runtime_setter!(
        feature = "auth-totp";
        with_auth_totp_output,
        auth_totp_output,
        RouterRuntime
    );
    runtime_setter!(
        feature = "mcp-transport-http";
        with_mcp_http_output,
        mcp_http_output,
        RouterHealthRuntime
    );
    runtime_setter!(
        feature = "mcp-auth-oauth";
        with_mcp_auth_oauth_output,
        mcp_auth_oauth_output,
        RouterRuntime
    );
    runtime_setter!(
        feature = "mcp-subscriptions-local";
        with_mcp_subscriptions_local_output,
        mcp_subscriptions_local_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "mcp-subscriptions-redis";
        with_mcp_subscriptions_redis_output,
        mcp_subscriptions_redis_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "mcp-subscriptions-nats";
        with_mcp_subscriptions_nats_output,
        mcp_subscriptions_nats_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "mcp-tasks";
        with_mcp_tasks_output,
        mcp_tasks_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "llm-provider-rig";
        with_llm_provider_rig_output,
        llm_provider_rig_output,
        HealthRuntime
    );
    runtime_setter!(
        feature = "llm-provider-bedrock";
        with_llm_provider_bedrock_output,
        llm_provider_bedrock_output,
        HealthRuntime
    );
    runtime_setter!(
        feature = "llm-provider-vertex";
        with_llm_provider_vertex_output,
        llm_provider_vertex_output,
        HealthRuntime
    );
    runtime_setter!(
        feature = "llm-routing";
        with_llm_routing_output,
        llm_routing_output,
        HealthRuntime
    );
    runtime_setter!(
        feature = "llm-tool-runtime";
        with_llm_tool_runtime_output,
        llm_tool_runtime_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "llm-media";
        with_llm_media_output,
        llm_media_output,
        TaskRuntime
    );
    runtime_setter!(
        feature = "llm-http-api";
        with_llm_http_api_output,
        llm_http_api_output,
        RouterRuntime
    );
}

/// Catalog criticality translated at the generated application boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionCriticality {
    /// Construction or final task failure makes the service unavailable.
    Required,
    /// Failure keeps the core service up while reporting degradation.
    Degraded,
    /// Failure is diagnostic and does not affect readiness.
    BestEffort,
}

impl From<CompositionCriticality> for Criticality {
    fn from(value: CompositionCriticality) -> Self {
        match value {
            CompositionCriticality::Required => Self::Required,
            CompositionCriticality::Degraded => Self::Degraded,
            CompositionCriticality::BestEffort => Self::BestEffort,
        }
    }
}

#[cfg(any(feature = "core", test))]
/// Selection-driven application builder populated by static registrars.
pub struct AppCompositionBuilder<'a> {
    input: CompositionInput,
    contributions: &'a mut ApplicationContributions,
    #[cfg(feature = "rate-limit-local")]
    application_rate_limiter: Option<omnius_rate_limit_local::LocalRateLimiter>,
    routers: Vec<Router>,
    health_specs: Vec<HealthCheckSpec>,
    health_runtime: bool,
    task_specs: Vec<TaskSpec>,
    route_ids: BTreeSet<&'static str>,
    health_ids: BTreeSet<&'static str>,
    task_ids: BTreeSet<&'static str>,
    public_operations: BTreeSet<&'static str>,
    capabilities: BTreeMap<&'static str, bool>,
}

#[cfg(any(feature = "core", test))]
impl<'a> AppCompositionBuilder<'a> {
    /// Creates a builder for one resolved profile and application boundary.
    #[must_use]
    pub fn new(input: CompositionInput, contributions: &'a mut ApplicationContributions) -> Self {
        Self {
            input,
            contributions,
            #[cfg(feature = "rate-limit-local")]
            application_rate_limiter: None,
            routers: Vec::new(),
            health_runtime: false,
            health_specs: Vec::new(),
            task_specs: Vec::new(),
            route_ids: BTreeSet::new(),
            health_ids: BTreeSet::new(),
            task_ids: BTreeSet::new(),
            public_operations: BTreeSet::new(),
            capabilities: BTreeMap::new(),
        }
    }

    /// Executes the generated prerequisite-first registrar list.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when a registrar cannot construct its
    /// selected contribution.
    pub fn register_selected(&mut self) -> Result<(), CompositionError> {
        catalog::register_selected(self)
    }

    #[cfg(feature = "core")]
    /// Records truthful compile/runtime capability availability.
    pub(crate) fn register_capability(
        &mut self,
        module: &'static str,
    ) -> Result<(), CompositionError> {
        let runtime_available = !self.input.runtime_disabled_modules.contains(&module);
        if self
            .capabilities
            .insert(module, runtime_available)
            .is_some()
        {
            return Err(CompositionError::DuplicateRegistration {
                kind: "capability",
                id: module,
            });
        }
        Ok(())
    }

    #[cfg(any(
        feature = "rate-limit-local",
        feature = "web-static",
        feature = "jobs-apalis-redis",
        feature = "jobs-pgmq",
        feature = "outbox",
        feature = "inbox",
        feature = "scheduler",
        feature = "events-nats",
        feature = "events-redis-ephemeral",
        feature = "realtime-core",
        feature = "sse",
        feature = "websockets",
        feature = "object-storage",
        feature = "email",
        feature = "notifications",
        feature = "webhooks-svix",
        feature = "webhooks-inbound",
        feature = "feature-flags",
        feature = "auth-oidc",
        feature = "auth-webauthn",
        feature = "auth-totp",
        feature = "mcp-server-core",
        feature = "mcp-transport-http",
        feature = "mcp-auth-oauth",
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        feature = "mcp-tasks",
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        feature = "llm-http-api"
    ))]
    pub(crate) fn runtime_available(&self, module: &str) -> bool {
        !self.input.runtime_disabled_modules.contains(&module)
    }

    #[cfg(feature = "http")]
    pub(crate) fn take_application_extension(
        &mut self,
    ) -> Result<ApplicationExtension, CompositionError> {
        self.contributions.application_extension.take().ok_or(
            CompositionError::MissingContribution {
                module: "http",
                contribution: "application.extension",
            },
        )
    }

    #[cfg(feature = "rate-limit-local")]
    pub(crate) fn application_rate_limit(
        &self,
        module: &'static str,
    ) -> Result<ApplicationRateLimitConfig, CompositionError> {
        self.contributions
            .application_rate_limit
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "application.rate-limit",
            })
    }

    #[cfg(feature = "rate-limit-local")]
    pub(crate) fn register_application_rate_limiter(
        &mut self,
        limiter: omnius_rate_limit_local::LocalRateLimiter,
    ) -> Result<(), CompositionError> {
        if self.application_rate_limiter.replace(limiter).is_some() {
            return Err(CompositionError::DuplicateRegistration {
                kind: "runtime",
                id: "application-rate-limiter",
            });
        }
        Ok(())
    }

    #[cfg(feature = "rate-limit-local")]
    pub(crate) fn take_application_rate_limiter(
        &mut self,
    ) -> Option<omnius_rate_limit_local::LocalRateLimiter> {
        self.application_rate_limiter.take()
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn postgres_pool(
        &self,
        module: &'static str,
    ) -> Result<&omnius_postgres::PostgresPool, CompositionError> {
        self.contributions
            .postgres_pool
            .as_ref()
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "postgres.pool",
            })
    }

    #[cfg(feature = "outbound-http")]
    pub(crate) fn register_outbound_http(&mut self) -> Result<(), CompositionError> {
        self.register_capability("outbound-http")?;
        self.contributions
            .outbound_http
            .as_ref()
            .ok_or(CompositionError::MissingContribution {
                module: "outbound-http",
                contribution: "outbound-http.clients",
            })?;
        Ok(())
    }

    #[cfg(feature = "idempotency")]
    pub(crate) fn idempotency_store(
        &self,
        module: &'static str,
    ) -> Result<omnius_idempotency::PostgresIdempotencyStore, CompositionError> {
        self.contributions
            .idempotency_store
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "idempotency.store",
            })
    }
    fn admin_auth_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "admin", test))]
            ApplicationRequirement::AdminAuthorityResolver => self
                .contributions
                .admin
                .as_ref()
                .map(|runtime| runtime.authority_resolver.is_some()),
            #[cfg(any(feature = "admin", test))]
            ApplicationRequirement::AdminOperationHandler => self
                .contributions
                .admin
                .as_ref()
                .map(|runtime| runtime.operation_handler.is_some()),
            #[cfg(any(
                feature = "auth-password",
                feature = "auth-session-postgres",
                feature = "auth-api-key",
                test
            ))]
            ApplicationRequirement::AuthAuthenticatedRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.authenticated.is_some()),
            #[cfg(any(feature = "auth-session-redis", test))]
            ApplicationRequirement::AuthRedisSessionRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.redis_session.is_some()),
            #[cfg(any(feature = "auth-oidc", test))]
            ApplicationRequirement::AuthOidcRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.oidc.is_some()),
            #[cfg(any(feature = "auth-oauth-server", test))]
            ApplicationRequirement::AuthOauthRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.oauth.is_some()),
            #[cfg(any(feature = "auth-webauthn", test))]
            ApplicationRequirement::AuthWebAuthnRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.webauthn.is_some()),
            #[cfg(any(feature = "auth-totp", test))]
            ApplicationRequirement::AuthTotpRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.totp.is_some()),
            _ => None,
        }
    }

    fn service_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "billing", test))]
            ApplicationRequirement::BillingProvider => self
                .contributions
                .billing
                .as_ref()
                .map(|runtime| runtime.provider.is_some()),
            #[cfg(any(feature = "feature-flags", test))]
            ApplicationRequirement::FeatureFlagsExposureRecorder => self
                .contributions
                .feature_flags
                .as_ref()
                .map(|runtime| runtime.exposure_recorder.is_some()),
            #[cfg(any(feature = "feature-flags", test))]
            ApplicationRequirement::FeatureFlagsProvider => self
                .contributions
                .feature_flags
                .as_ref()
                .map(|runtime| runtime.provider.is_some()),
            #[cfg(any(feature = "graphql", test))]
            ApplicationRequirement::GraphqlRequestDataInjector => self
                .contributions
                .graphql
                .as_ref()
                .map(|runtime| runtime.request_data_injector.is_some()),
            #[cfg(any(feature = "graphql", test))]
            ApplicationRequirement::GraphqlSchema => self
                .contributions
                .graphql
                .as_ref()
                .map(|runtime| runtime.schema.is_some()),
            #[cfg(any(feature = "grpc", test))]
            ApplicationRequirement::GrpcApplicationService => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.application_service.is_some()),
            #[cfg(any(feature = "grpc", test))]
            ApplicationRequirement::GrpcAuthenticator => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.authenticator.is_some()),
            #[cfg(any(feature = "grpc", test))]
            ApplicationRequirement::GrpcMethodPolicies => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.method_policies.is_some()),
            #[cfg(any(feature = "inbox", test))]
            ApplicationRequirement::InboxConsumers => self
                .contributions
                .inbox
                .as_ref()
                .map(|runtime| runtime.consumers.is_some()),
            #[cfg(any(feature = "jobs-core", test))]
            ApplicationRequirement::JobsHandlers => self
                .contributions
                .jobs
                .as_ref()
                .map(|runtime| runtime.handlers.is_some()),
            _ => None,
        }
    }

    fn llm_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(test)]
            ApplicationRequirement::LlmEvaluationRepository => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.evaluation_repository.is_some()),
            #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
            ApplicationRequirement::LlmMediaAuthorization => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.media_authorization.is_some()),
            #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
            ApplicationRequirement::LlmMediaScanner => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.media_scanner.is_some()),
            #[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
            ApplicationRequirement::LlmToolAudit => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.tool_audit.is_some()),
            #[cfg(any(
                feature = "llm-provider-rig",
                feature = "llm-tool-runtime",
                feature = "llm-http-api",
                test
            ))]
            ApplicationRequirement::LlmToolAuthorization => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.tool_authorization.is_some()),
            _ => None,
        }
    }

    fn mcp_core_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "mcp-apps", test))]
            ApplicationRequirement::McpAppsPorts => self
                .contributions
                .mcp_apps
                .as_ref()
                .map(|runtime| runtime.ports.is_some()),
            #[cfg(any(feature = "mcp-transport-http", test))]
            ApplicationRequirement::McpBearerAuthenticator => self
                .contributions
                .mcp_auth
                .as_ref()
                .map(|runtime| runtime.bearer_authenticator.is_some()),
            #[cfg(any(feature = "mcp-tasks", test))]
            ApplicationRequirement::McpCancellationRuntime => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.cancellation_runtime.is_some()),
            #[cfg(any(feature = "mcp-tasks", test))]
            ApplicationRequirement::McpCapabilityExecutor => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.capability_executor.is_some()),
            #[cfg(any(feature = "mcp-server-core", test))]
            ApplicationRequirement::McpCapabilityRegistry => self
                .contributions
                .mcp_core
                .as_ref()
                .map(|runtime| runtime.capability_registry.is_some()),
            #[cfg(any(feature = "mcp-auth-enterprise", test))]
            ApplicationRequirement::McpEnterprisePorts => self
                .contributions
                .mcp_enterprise
                .as_ref()
                .map(|runtime| runtime.ports.is_some()),
            _ => None,
        }
    }

    fn mcp_work_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionAuthorizer => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.authorizer.is_some()),
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionDelivery => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.delivery.is_some()),
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionRepository => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.repository.is_some()),
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionRuntime => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.runtime.is_some()),
            #[cfg(any(feature = "mcp-tasks", test))]
            ApplicationRequirement::McpTaskPayloadProtector => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.payload_protector.is_some()),
            _ => None,
        }
    }

    fn data_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "outbox", test))]
            ApplicationRequirement::OutboxPublisher => self
                .contributions
                .outbox
                .as_ref()
                .map(|runtime| runtime.publisher.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyAuthorizer => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.authorizer.is_some()),
            #[cfg(any(feature = "consent", test))]
            ApplicationRequirement::PrivacyConsentPolicy => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.consent_policy.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyInventoryAdapters => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.inventory_adapters.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyInventoryManifest => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.inventory_manifest.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyLifecycleHandler => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.lifecycle_handler.is_some()),
            #[cfg(any(feature = "moderation", test))]
            ApplicationRequirement::PrivacyModerationPolicy => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.moderation_policy.is_some()),
            _ => None,
        }
    }

    fn delivery_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(
                feature = "redis-core",
                feature = "events-nats",
                feature = "realtime-core",
                test
            ))]
            ApplicationRequirement::RealtimeEventHandler => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.event_handler.is_some()),
            #[cfg(any(feature = "realtime-core", test))]
            ApplicationRequirement::RealtimeFanoutAuthorizer => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.fanout_authorizer.is_some()),
            #[cfg(any(feature = "realtime-core", test))]
            ApplicationRequirement::RealtimeIdentityRevalidator => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.identity_revalidator.is_some()),
            #[cfg(any(feature = "scheduler", test))]
            ApplicationRequirement::SchedulerEnvelopeFactory => self
                .contributions
                .scheduler
                .as_ref()
                .map(|runtime| runtime.envelope_factory.is_some()),
            #[cfg(any(feature = "search-meilisearch", test))]
            ApplicationRequirement::SearchIndexSchema => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.index_schema.is_some()),
            #[cfg(any(feature = "search-meilisearch", test))]
            ApplicationRequirement::SearchProjectionResolver => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.projection_resolver.is_some()),
            #[cfg(any(feature = "search-meilisearch", test))]
            ApplicationRequirement::SearchReauthorizer => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.reauthorizer.is_some()),
            #[cfg(any(feature = "object-storage", test))]
            ApplicationRequirement::UploadsAuthorization => self
                .contributions
                .uploads
                .as_ref()
                .map(|runtime| runtime.authorization.is_some()),
            #[cfg(any(feature = "object-storage", test))]
            ApplicationRequirement::UploadsWorkflow => self
                .contributions
                .uploads
                .as_ref()
                .map(|runtime| runtime.workflow.is_some()),
            #[cfg(any(feature = "webhooks-inbound", test))]
            ApplicationRequirement::WebhooksInboundHandlers => self
                .contributions
                .webhooks_inbound
                .as_ref()
                .map(|runtime| runtime.handlers.is_some()),
            #[cfg(any(feature = "webhooks-inbound", test))]
            ApplicationRequirement::WebhooksInboundProviderAdapters => self
                .contributions
                .webhooks_inbound
                .as_ref()
                .map(|runtime| runtime.provider_adapters.is_some()),
            #[cfg(any(feature = "webhooks-svix", test))]
            ApplicationRequirement::WebhooksSvixReplayAdmission => self
                .contributions
                .webhooks_svix
                .as_ref()
                .map(|runtime| runtime.replay_admission.is_some()),
            _ => None,
        }
    }

    fn requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            ApplicationRequirement::AdminAuthorityResolver
            | ApplicationRequirement::AdminOperationHandler
            | ApplicationRequirement::AuthAuthenticatedRuntime
            | ApplicationRequirement::AuthRedisSessionRuntime
            | ApplicationRequirement::AuthOidcRuntime
            | ApplicationRequirement::AuthOauthRuntime
            | ApplicationRequirement::AuthWebAuthnRuntime
            | ApplicationRequirement::AuthTotpRuntime => {
                self.admin_auth_requirement_present(requirement)
            }
            ApplicationRequirement::BillingProvider
            | ApplicationRequirement::FeatureFlagsExposureRecorder
            | ApplicationRequirement::FeatureFlagsProvider
            | ApplicationRequirement::GraphqlRequestDataInjector
            | ApplicationRequirement::GraphqlSchema
            | ApplicationRequirement::GrpcApplicationService
            | ApplicationRequirement::GrpcAuthenticator
            | ApplicationRequirement::GrpcMethodPolicies
            | ApplicationRequirement::InboxConsumers
            | ApplicationRequirement::JobsHandlers => self.service_requirement_present(requirement),
            ApplicationRequirement::LlmEvaluationRepository
            | ApplicationRequirement::LlmMediaAuthorization
            | ApplicationRequirement::LlmMediaScanner
            | ApplicationRequirement::LlmToolAudit
            | ApplicationRequirement::LlmToolAuthorization => {
                self.llm_requirement_present(requirement)
            }
            ApplicationRequirement::McpAppsPorts
            | ApplicationRequirement::McpBearerAuthenticator
            | ApplicationRequirement::McpCancellationRuntime
            | ApplicationRequirement::McpCapabilityExecutor
            | ApplicationRequirement::McpCapabilityRegistry
            | ApplicationRequirement::McpEnterprisePorts => {
                self.mcp_core_requirement_present(requirement)
            }
            ApplicationRequirement::McpSubscriptionAuthorizer
            | ApplicationRequirement::McpSubscriptionDelivery
            | ApplicationRequirement::McpSubscriptionRepository
            | ApplicationRequirement::McpSubscriptionRuntime
            | ApplicationRequirement::McpTaskPayloadProtector => {
                self.mcp_work_requirement_present(requirement)
            }
            ApplicationRequirement::OutboxPublisher
            | ApplicationRequirement::PrivacyAuthorizer
            | ApplicationRequirement::PrivacyConsentPolicy
            | ApplicationRequirement::PrivacyInventoryAdapters
            | ApplicationRequirement::PrivacyInventoryManifest
            | ApplicationRequirement::PrivacyLifecycleHandler
            | ApplicationRequirement::PrivacyModerationPolicy => {
                self.data_requirement_present(requirement)
            }
            ApplicationRequirement::RealtimeEventHandler
            | ApplicationRequirement::RealtimeFanoutAuthorizer
            | ApplicationRequirement::RealtimeIdentityRevalidator
            | ApplicationRequirement::SchedulerEnvelopeFactory
            | ApplicationRequirement::SearchIndexSchema
            | ApplicationRequirement::SearchProjectionResolver
            | ApplicationRequirement::SearchReauthorizer
            | ApplicationRequirement::UploadsAuthorization
            | ApplicationRequirement::UploadsWorkflow
            | ApplicationRequirement::WebhooksInboundHandlers
            | ApplicationRequirement::WebhooksInboundProviderAdapters
            | ApplicationRequirement::WebhooksSvixReplayAdmission => {
                self.delivery_requirement_present(requirement)
            }
        }
    }

    /// Validates one generated application requirement against its exact typed field.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::MissingContribution`] when the required
    /// runtime family is unavailable, or [`CompositionError::ContractMismatch`]
    /// when that family exists without the required typed port.
    pub fn require(
        &self,
        module: &'static str,
        requirement: ApplicationRequirement,
    ) -> Result<(), CompositionError> {
        match self.requirement_present(requirement) {
            None => Err(CompositionError::MissingContribution {
                module,
                contribution: requirement.as_str(),
            }),
            Some(false) => Err(CompositionError::ContractMismatch {
                kind: "application-requirement",
                id: requirement.as_str(),
            }),
            Some(true) => Ok(()),
        }
    }

    #[cfg(any(
        feature = "web-static",
        feature = "jobs-apalis-redis",
        feature = "jobs-pgmq",
        feature = "outbox",
        feature = "inbox",
        feature = "scheduler",
        feature = "events-nats",
        feature = "events-redis-ephemeral",
        feature = "realtime-core",
        feature = "sse",
        feature = "websockets",
        feature = "object-storage",
        feature = "email",
        feature = "notifications",
        feature = "webhooks-svix",
        feature = "webhooks-inbound",
        feature = "feature-flags",
        feature = "auth-oidc",
        feature = "auth-webauthn",
        feature = "auth-totp",
        feature = "mcp-server-core",
        feature = "mcp-transport-http",
        feature = "mcp-auth-oauth",
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        feature = "mcp-tasks",
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        feature = "llm-http-api"
    ))]
    fn prepare_module(&mut self, module: &'static str) -> Result<bool, CompositionError> {
        self.register_capability(module)?;
        if !self.runtime_available(module) {
            return Ok(false);
        }
        if let Some(contract) = self
            .input
            .contracts
            .iter()
            .find(|contract| contract.module == module)
        {
            for requirement in contract.application_requirements {
                self.require(module, *requirement)?;
            }
        }
        Ok(true)
    }

    #[cfg(any(
        feature = "web-static",
        feature = "jobs-apalis-redis",
        feature = "jobs-pgmq",
        feature = "outbox",
        feature = "scheduler",
        feature = "events-nats",
        feature = "events-redis-ephemeral",
        feature = "sse",
        feature = "websockets",
        feature = "object-storage",
        feature = "email",
        feature = "notifications",
        feature = "webhooks-svix",
        feature = "webhooks-inbound",
        feature = "auth-oidc",
        feature = "auth-webauthn",
        feature = "auth-totp",
        feature = "mcp-transport-http",
        feature = "mcp-auth-oauth",
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        feature = "mcp-tasks",
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        feature = "llm-http-api"
    ))]
    fn missing_runtime(module: &'static str) -> CompositionError {
        CompositionError::ContractMismatch {
            kind: "runtime",
            id: module,
        }
    }

    #[cfg(feature = "web-static")]
    pub(crate) fn register_web_static(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("web-static")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .web_static_output
            .take()
            .ok_or_else(|| Self::missing_runtime("web-static"))?;
        self.register_router(
            runtime.router,
            &["GET/HEAD /assets/*", "GET/HEAD <spa-fallback>"],
        )
    }

    #[cfg(feature = "jobs-apalis-redis")]
    pub(crate) fn register_jobs_apalis_redis(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("jobs-apalis-redis")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .jobs_apalis_redis_output
            .take()
            .ok_or_else(|| Self::missing_runtime("jobs-apalis-redis"))?;
        self.register_task("job-worker", runtime.worker)?;
        self.register_health("job-backend", runtime.readiness)
    }

    #[cfg(feature = "jobs-pgmq")]
    pub(crate) fn register_jobs_pgmq(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("jobs-pgmq")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .jobs_pgmq_output
            .take()
            .ok_or_else(|| Self::missing_runtime("jobs-pgmq"))?;
        self.register_task("job-worker", runtime.worker)?;
        self.register_health("job-backend", runtime.readiness)
    }

    #[cfg(feature = "outbox")]
    pub(crate) fn register_outbox(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("outbox")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .outbox_output
            .take()
            .ok_or_else(|| Self::missing_runtime("outbox"))?;
        self.register_task("outbox-relay", runtime.task)
    }

    #[cfg(feature = "inbox")]
    pub(crate) fn register_inbox(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("inbox").map(|_| ())
    }

    #[cfg(feature = "scheduler")]
    pub(crate) fn register_scheduler(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("scheduler")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .scheduler_output
            .take()
            .ok_or_else(|| Self::missing_runtime("scheduler"))?;
        self.register_task("scheduler", runtime.task)
    }

    #[cfg(feature = "events-nats")]
    pub(crate) fn register_events_nats(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("events-nats")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .events_nats_output
            .take()
            .ok_or_else(|| Self::missing_runtime("events-nats"))?;
        self.register_task("nats-consumers", runtime.task)?;
        self.register_health("nats-jetstream", runtime.health)
    }

    #[cfg(feature = "events-redis-ephemeral")]
    pub(crate) fn register_events_redis(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("events-redis-ephemeral")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .events_redis_output
            .take()
            .ok_or_else(|| Self::missing_runtime("events-redis-ephemeral"))?;
        self.register_task("redis-pubsub-listener", runtime.task)
    }

    #[cfg(feature = "realtime-core")]
    pub(crate) fn register_realtime_core(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("realtime-core").map(|_| ())
    }

    #[cfg(feature = "sse")]
    pub(crate) fn register_sse(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("sse")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .sse_output
            .take()
            .ok_or_else(|| Self::missing_runtime("sse"))?;
        self.register_router(runtime.router, &["/realtime/events"])
    }

    #[cfg(feature = "websockets")]
    pub(crate) fn register_websockets(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("websockets")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .websockets_output
            .take()
            .ok_or_else(|| Self::missing_runtime("websockets"))?;
        self.register_router(runtime.router, &["/realtime/ws"])
    }

    #[cfg(feature = "object-storage")]
    pub(crate) fn register_object_storage(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("object-storage")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .object_storage_output
            .take()
            .ok_or_else(|| Self::missing_runtime("object-storage"))?;
        self.register_health("object-store", runtime.health)
    }

    #[cfg(feature = "email")]
    pub(crate) fn register_email(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("email")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .email_output
            .take()
            .ok_or_else(|| Self::missing_runtime("email"))?;
        self.register_health("email-provider", runtime.health)
    }

    #[cfg(feature = "notifications")]
    pub(crate) fn register_notifications(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("notifications")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .notifications_output
            .take()
            .ok_or_else(|| Self::missing_runtime("notifications"))?;
        self.register_task("notification-orchestrator", runtime.task)
    }

    #[cfg(feature = "webhooks-svix")]
    pub(crate) fn register_webhooks_svix(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("webhooks-svix")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .webhooks_svix_output
            .take()
            .ok_or_else(|| Self::missing_runtime("webhooks-svix"))?;
        self.register_health("svix", runtime.health)
    }

    #[cfg(feature = "webhooks-inbound")]
    pub(crate) fn register_webhooks_inbound(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("webhooks-inbound")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .webhooks_inbound_output
            .take()
            .ok_or_else(|| Self::missing_runtime("webhooks-inbound"))?;
        self.register_router(runtime.router, &["/webhooks/inbound/{provider}"])?;
        self.register_task("inbound-webhook-processor", runtime.task)
    }

    #[cfg(feature = "feature-flags")]
    pub(crate) fn register_feature_flags(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("feature-flags").map(|_| ())
    }

    #[cfg(feature = "auth-oidc")]
    pub(crate) fn register_auth_oidc(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-oidc")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth_oidc_output
            .take()
            .ok_or_else(|| Self::missing_runtime("auth-oidc"))?;
        self.register_router(
            runtime.router,
            &[
                "/auth/oidc/{provider}/start",
                "/auth/oidc/{provider}/callback",
            ],
        )?;
        self.register_task("oidc-pending-authorization-cleanup", runtime.task)
    }

    #[cfg(feature = "auth-webauthn")]
    pub(crate) fn register_auth_webauthn(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-webauthn")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth_webauthn_output
            .take()
            .ok_or_else(|| Self::missing_runtime("auth-webauthn"))?;
        self.register_router(
            runtime.router,
            &[
                "/auth/passkeys",
                "/auth/passkeys/register/start",
                "/auth/passkeys/register/finish",
                "/auth/passkeys/authenticate/start",
                "/auth/passkeys/authenticate/finish",
            ],
        )
    }

    #[cfg(feature = "auth-totp")]
    pub(crate) fn register_auth_totp(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-totp")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth_totp_output
            .take()
            .ok_or_else(|| Self::missing_runtime("auth-totp"))?;
        self.register_router(
            runtime.router,
            &[
                "/auth/mfa/totp/enroll",
                "/auth/mfa/totp/confirm",
                "/auth/mfa/totp/disable",
            ],
        )
    }

    #[cfg(feature = "mcp-server-core")]
    pub(crate) fn register_mcp_core(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("mcp-server-core").map(|_| ())
    }

    #[cfg(feature = "mcp-transport-http")]
    pub(crate) fn register_mcp_http(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("mcp-transport-http")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .mcp_http_output
            .take()
            .ok_or_else(|| Self::missing_runtime("mcp-transport-http"))?;
        self.register_router(runtime.router, &["POST /mcp"])?;
        self.register_health("mcp-http-dispatch", runtime.health)?;
        self.register_public_operation("mcp.dispatch")
    }

    #[cfg(feature = "mcp-auth-oauth")]
    pub(crate) fn register_mcp_auth_oauth(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("mcp-auth-oauth")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .mcp_auth_oauth_output
            .take()
            .ok_or_else(|| Self::missing_runtime("mcp-auth-oauth"))?;
        self.register_router(
            runtime.router,
            &["GET /.well-known/oauth-protected-resource"],
        )?;
        self.register_public_operation("mcp.oauthProtectedResourceMetadata")
    }

    #[cfg(feature = "mcp-subscriptions-local")]
    pub(crate) fn register_mcp_subscriptions_local(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-local", |c| {
            c.mcp_subscriptions_local_output.take()
        })
    }

    #[cfg(feature = "mcp-subscriptions-redis")]
    pub(crate) fn register_mcp_subscriptions_redis(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-redis", |c| {
            c.mcp_subscriptions_redis_output.take()
        })
    }

    #[cfg(feature = "mcp-subscriptions-nats")]
    pub(crate) fn register_mcp_subscriptions_nats(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-nats", |c| {
            c.mcp_subscriptions_nats_output.take()
        })
    }

    #[cfg(any(
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats"
    ))]
    fn register_mcp_subscription_output(
        &mut self,
        module: &'static str,
        take: impl FnOnce(&mut ApplicationContributions) -> Option<TaskRuntime>,
    ) -> Result<(), CompositionError> {
        if !self.prepare_module(module)? {
            return Ok(());
        }
        let runtime = take(self.contributions).ok_or_else(|| Self::missing_runtime(module))?;
        self.register_task("mcp-subscription-backplane", runtime.task)
    }

    #[cfg(feature = "mcp-tasks")]
    pub(crate) fn register_mcp_tasks(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("mcp-tasks")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .mcp_tasks_output
            .take()
            .ok_or_else(|| Self::missing_runtime("mcp-tasks"))?;
        self.register_task("mcp-task-expiry", runtime.task)
    }

    #[cfg(feature = "llm-provider-rig")]
    pub(crate) fn register_llm_provider_rig(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output(
            "llm-provider-rig",
            "configured-provider-route-availability",
            |c| c.llm_provider_rig_output.take(),
        )
    }

    #[cfg(feature = "llm-provider-bedrock")]
    pub(crate) fn register_llm_provider_bedrock(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-bedrock", "bedrock-route-availability", |c| {
            c.llm_provider_bedrock_output.take()
        })
    }

    #[cfg(feature = "llm-provider-vertex")]
    pub(crate) fn register_llm_provider_vertex(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-vertex", "vertex-route-availability", |c| {
            c.llm_provider_vertex_output.take()
        })
    }

    #[cfg(feature = "llm-routing")]
    pub(crate) fn register_llm_routing(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-routing", "required-route-availability", |c| {
            c.llm_routing_output.take()
        })
    }

    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing"
    ))]
    fn register_llm_health_output(
        &mut self,
        module: &'static str,
        health_id: &'static str,
        take: impl FnOnce(&mut ApplicationContributions) -> Option<HealthRuntime>,
    ) -> Result<(), CompositionError> {
        if !self.prepare_module(module)? {
            return Ok(());
        }
        let runtime = take(self.contributions).ok_or_else(|| Self::missing_runtime(module))?;
        self.register_health(health_id, runtime.health)
    }

    #[cfg(feature = "llm-tool-runtime")]
    pub(crate) fn register_llm_tool_runtime(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("llm-tool-runtime")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .llm_tool_runtime_output
            .take()
            .ok_or_else(|| Self::missing_runtime("llm-tool-runtime"))?;
        self.register_task("tool-approval-expiry", runtime.task)
    }

    #[cfg(feature = "llm-media")]
    pub(crate) fn register_llm_media(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("llm-media")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .llm_media_output
            .take()
            .ok_or_else(|| Self::missing_runtime("llm-media"))?;
        self.register_task("llm-media-reconciliation", runtime.task)
    }

    #[cfg(feature = "llm-http-api")]
    pub(crate) fn register_llm_http_api(&mut self) -> Result<(), CompositionError> {
        const ROUTES: &[&str] = &[
            "GET /api/ai/routes",
            "POST /api/ai/responses",
            "POST /api/ai/responses/stream",
            "POST /api/ai/jobs",
            "GET /api/ai/jobs/{job_id}",
            "DELETE /api/ai/jobs/{job_id}",
            "GET /api/ai/jobs/{job_id}/result",
            "POST /api/ai/conversations",
            "GET /api/ai/conversations/{conversation_id}",
            "DELETE /api/ai/conversations/{conversation_id}",
            "GET /api/ai/conversations/{conversation_id}/messages",
            "POST /api/ai/conversations/{conversation_id}/messages",
            "PATCH /api/ai/conversations/{conversation_id}/messages/{message_id}",
            "DELETE /api/ai/conversations/{conversation_id}/messages/{message_id}",
            "GET /api/ai/conversations/{conversation_id}/provider-state/{state_id}",
            "PUT /api/ai/conversations/{conversation_id}/provider-state/{state_id}",
            "DELETE /api/ai/conversations/{conversation_id}/provider-state/{state_id}",
        ];
        const OPERATIONS: &[&str] = &[
            "aiRoutesList",
            "aiResponseCreate",
            "aiResponseStream",
            "aiJobSubmit",
            "aiJobGet",
            "aiJobCancel",
            "aiJobResult",
            "aiConversationCreate",
            "aiConversationGet",
            "aiConversationDelete",
            "aiConversationMessagesList",
            "aiConversationMessageAppend",
            "aiConversationMessageUpdate",
            "aiConversationMessageDelete",
            "aiConversationProviderStateGet",
            "aiConversationProviderStatePut",
            "aiConversationProviderStateDelete",
        ];
        if !self.prepare_module("llm-http-api")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .llm_http_api_output
            .take()
            .ok_or_else(|| Self::missing_runtime("llm-http-api"))?;
        self.register_router(runtime.router, ROUTES)?;
        for operation in OPERATIONS {
            self.register_public_operation(operation)?;
        }
        Ok(())
    }

    /// Mounts a router and records exactly the route IDs it serves.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if any route ID was
    /// already registered.
    pub fn register_router(
        &mut self,
        router: Router,
        route_ids: &'static [&'static str],
    ) -> Result<(), CompositionError> {
        insert_ids(&mut self.route_ids, "route", route_ids)?;
        self.routers.push(router);
        Ok(())
    }

    /// Registers one cached health check and its catalog ID.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if `id` was already
    /// registered as a health check.
    pub fn register_health(
        &mut self,
        id: &'static str,
        spec: HealthCheckSpec,
    ) -> Result<(), CompositionError> {
        if !self.health_ids.insert(id) {
            return Err(CompositionError::DuplicateRegistration { kind: "health", id });
        }
        self.health_specs.push(spec);
        Ok(())
    }

    /// Registers one supervised task and its catalog ID.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if `id` was already
    /// registered as a task.
    pub fn register_task(
        &mut self,
        id: &'static str,
        spec: TaskSpec,
    ) -> Result<(), CompositionError> {
        if !self.task_ids.insert(id) {
            return Err(CompositionError::DuplicateRegistration { kind: "task", id });
        }
        self.task_specs.push(spec);
        Ok(())
    }
    #[cfg(feature = "health")]
    pub(crate) fn register_health_runtime(&mut self) -> Result<(), CompositionError> {
        const ROUTES: &[&str] = &["/live", "/ready", "/startup", "/version"];
        const TASKS: &[&str] = &["health-cache-refresh"];

        if self.health_runtime {
            return Err(CompositionError::DuplicateRegistration {
                kind: "runtime",
                id: "health",
            });
        }
        insert_ids(&mut self.route_ids, "route", ROUTES)?;
        insert_ids(&mut self.task_ids, "task", TASKS)?;
        self.health_runtime = true;
        Ok(())
    }

    /// Records one public operation served by a mounted composition router.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if `operation` was
    /// already registered.
    pub fn register_public_operation(
        &mut self,
        operation: &'static str,
    ) -> Result<(), CompositionError> {
        if !self.public_operations.insert(operation) {
            return Err(CompositionError::DuplicateRegistration {
                kind: "operation",
                id: operation,
            });
        }
        Ok(())
    }

    #[cfg(feature = "openapi")]
    pub(crate) fn install_openapi_catalog(
        &mut self,
        document: serde_json::Value,
        operations: &[ExpectedOperation],
    ) -> Result<(), CompositionError> {
        const ROUTES: &[&str] = &["/openapi.json", "/docs"];

        let enabled = self.input.contracts.iter().any(|contract| {
            contract.module == "openapi"
                && (!contract.runtime_toggle
                    || !self
                        .input
                        .runtime_disabled_modules
                        .contains(&contract.module))
        });
        if !enabled {
            return Ok(());
        }
        let config =
            self.contributions
                .openapi_config
                .ok_or(CompositionError::MissingContribution {
                    module: "openapi",
                    contribution: "openapi.config",
                })?;
        if !config.document_route_enabled || !config.docs_route_enabled {
            return Err(CompositionError::InvalidConfiguration { module: "openapi" });
        }
        omnius_openapi::validate_operation_coverage_value(&document, operations)
            .map_err(|error| CompositionError::construction("openapi", error))?;
        let catalog = omnius_openapi::OpenApiCatalog::try_from_value(document, config)
            .map_err(|error| CompositionError::construction("openapi", error))?;
        self.register_router(catalog.router(), ROUTES)
    }

    /// Validates application requirements and catalog-to-runtime registration.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] for missing application policy, duplicate
    /// registrations, or any declared route/task/health contract that was not
    /// actually registered.
    pub fn finish(self) -> Result<ComposedApplication, CompositionError> {
        let builder = self;
        for contract in builder.input.contracts {
            let enabled = !contract.runtime_toggle
                || !builder
                    .input
                    .runtime_disabled_modules
                    .contains(&contract.module);
            if !enabled {
                continue;
            }
            for requirement in contract.application_requirements {
                builder.require(contract.module, *requirement)?;
            }
        }
        validate_contract_ids(
            builder.input.contracts,
            builder.input.runtime_disabled_modules,
            "route",
            |contract| contract.routes,
            &builder.route_ids,
        )?;
        validate_contract_ids(
            builder.input.contracts,
            builder.input.runtime_disabled_modules,
            "task",
            |contract| contract.tasks,
            &builder.task_ids,
        )?;
        validate_contract_ids(
            builder.input.contracts,
            builder.input.runtime_disabled_modules,
            "health",
            |contract| contract.health_checks,
            &builder.health_ids,
        )?;
        let router = builder
            .routers
            .into_iter()
            .fold(Router::new(), Router::merge);
        Ok(ComposedApplication {
            router,
            health_runtime: builder.health_runtime,
            health_specs: builder.health_specs,
            task_specs: builder.task_specs,
            public_operations: builder.public_operations,
            capabilities: builder.capabilities,
        })
    }
}

/// Fully validated output of the generated static registrar graph.
pub struct ComposedApplication {
    router: Router,
    health_specs: Vec<HealthCheckSpec>,
    health_runtime: bool,
    task_specs: Vec<TaskSpec>,
    public_operations: BTreeSet<&'static str>,
    capabilities: BTreeMap<&'static str, bool>,
}

impl ComposedApplication {
    /// Consumes the composition into its router, cached health checks, deferred
    /// health-runtime marker, and supervised tasks.
    #[must_use = "the composed runtime parts must be installed into the application process"]
    pub fn into_runtime_parts(self) -> (Router, Vec<HealthCheckSpec>, bool, Vec<TaskSpec>) {
        (
            self.router,
            self.health_specs,
            self.health_runtime,
            self.task_specs,
        )
    }

    /// Returns registered cached health checks.
    #[must_use]
    pub fn health_specs(&self) -> &[HealthCheckSpec] {
        &self.health_specs
    }

    /// Returns registered supervised tasks.
    #[must_use]
    pub fn task_specs(&self) -> &[TaskSpec] {
        &self.task_specs
    }

    /// Returns mounted public operation IDs.
    #[must_use]
    pub fn public_operations(&self) -> &BTreeSet<&'static str> {
        &self.public_operations
    }

    /// Returns compiled capabilities and runtime availability.
    #[must_use]
    pub fn capabilities(&self) -> &BTreeMap<&'static str, bool> {
        &self.capabilities
    }
}

/// Static application composition failure.
#[derive(Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// Generated module IDs differ from the ordered compiled feature set.
    SelectionMismatch,
    /// A known runtime module was selected without compiling its feature.
    FeatureNotEnabled {
        /// Selected module ID.
        module: &'static str,
    },
    /// A selected module ID is not a runtime module in the catalog.
    UnknownModule {
        /// Selected module ID.
        module: &'static str,
    },
    /// A selected module requires an application-owned domain port.
    MissingContribution {
        /// Selected module ID.
        module: &'static str,
        /// Stable contribution requirement.
        contribution: &'static str,
    },
    /// A command is structurally unavailable in the selected profile.
    CommandUnavailable {
        /// Selected profile ID.
        profile: &'static str,
        /// Requested command.
        command: &'static str,
    },
    /// The same runtime contract was registered twice.
    DuplicateRegistration {
        /// Contract kind.
        kind: &'static str,
        /// Contract ID.
        id: &'static str,
    },
    /// A selected catalog contract was not registered by its owning module.
    ContractMismatch {
        /// Contract kind.
        kind: &'static str,
        /// Contract ID.
        id: &'static str,
    },
    /// A selected built-in registrar rejected its typed configuration.
    InvalidConfiguration {
        /// Selected module ID.
        module: &'static str,
    },
}

impl CompositionError {
    /// Creates the canonical error for a command absent from the selected composition.
    #[must_use]
    pub const fn command_unavailable(profile: &'static str, command: &'static str) -> Self {
        Self::CommandUnavailable { profile, command }
    }

    #[cfg(any(feature = "postgres", feature = "outbound-http", feature = "openapi"))]
    pub(crate) fn construction(module: &'static str, _error: impl Error) -> Self {
        Self::InvalidConfiguration { module }
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionMismatch => formatter.write_str(
                "selected modules do not match the ordered compiled service-kit features",
            ),
            Self::FeatureNotEnabled { module } => {
                write!(
                    formatter,
                    "module `{module}` is not enabled in this service-kit build"
                )
            }
            Self::UnknownModule { module } => {
                write!(formatter, "module `{module}` is not a known runtime module")
            }
            Self::MissingContribution {
                module,
                contribution,
            } => write!(
                formatter,
                "module `{module}` requires application contribution `{contribution}`"
            ),
            Self::CommandUnavailable { profile, command } => write!(
                formatter,
                "command `{command}` is unavailable for profile `{profile}`"
            ),
            Self::DuplicateRegistration { kind, id } => {
                write!(formatter, "duplicate {kind} registration `{id}`")
            }
            Self::ContractMismatch { kind, id } => {
                write!(
                    formatter,
                    "selected {kind} contract `{id}` was not registered"
                )
            }
            Self::InvalidConfiguration { module } => {
                write!(formatter, "module `{module}` configuration is invalid")
            }
        }
    }
}

impl Error for CompositionError {}

#[cfg(any(feature = "core", test))]
fn insert_ids(
    target: &mut BTreeSet<&'static str>,
    kind: &'static str,
    ids: &'static [&'static str],
) -> Result<(), CompositionError> {
    for id in ids {
        if !target.insert(id) {
            return Err(CompositionError::DuplicateRegistration { kind, id });
        }
    }
    Ok(())
}

#[cfg(any(feature = "core", test))]
fn validate_contract_ids(
    contracts: &'static [SelectedModuleContract],
    disabled_modules: &'static [&'static str],
    kind: &'static str,
    ids: impl Fn(&SelectedModuleContract) -> &'static [&'static str],
    registered: &BTreeSet<&'static str>,
) -> Result<(), CompositionError> {
    for contract in contracts {
        if contract.runtime_toggle && disabled_modules.contains(&contract.module) {
            continue;
        }
        for id in ids(contract) {
            if !registered.contains(id) {
                return Err(CompositionError::ContractMismatch { kind, id });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    struct ContractProbe;

    impl AdminAuthorityResolverPort for ContractProbe {
        fn authorizes(&self, principal: &str, action: &str) -> bool {
            !principal.is_empty() && !action.is_empty()
        }
    }
    impl AdminOperationHandlerPort for ContractProbe {
        fn execute(&self, operation: &str) -> bool {
            !operation.is_empty()
        }
    }
    impl AuthenticatedRuntimePort for ContractProbe {
        fn authenticate(&self, credential: &str) -> Option<String> {
            (!credential.is_empty()).then(|| "subject".to_owned())
        }
    }
    impl RedisSessionRuntimePort for ContractProbe {
        fn session_is_live(&self, session_id: &str) -> bool {
            !session_id.is_empty()
        }
    }
    impl OidcRuntimePort for ContractProbe {
        fn supports_provider(&self, provider: &str) -> bool {
            !provider.is_empty()
        }
    }
    impl OauthRuntimePort for ContractProbe {
        fn authorizes_client_scope(&self, client_id: &str, scope: &str) -> bool {
            !client_id.is_empty() && !scope.is_empty()
        }
    }
    impl WebauthnRuntimePort for ContractProbe {
        fn accepts_origin(&self, origin: &str) -> bool {
            origin.starts_with("https://")
        }
    }
    impl TotpRuntimePort for ContractProbe {
        fn verifies_code(&self, subject: &str, code: &str) -> bool {
            !subject.is_empty() && code.len() == 6
        }
    }
    impl JobsHandlersPort for ContractProbe {
        fn handles(&self, job_name: &str) -> bool {
            !job_name.is_empty()
        }
    }
    impl OutboxPublisherPort for ContractProbe {
        fn publish(&self, event_id: &str, payload: &[u8]) -> bool {
            !event_id.is_empty() && !payload.is_empty()
        }
    }
    impl InboxConsumersPort for ContractProbe {
        fn consume(&self, message_name: &str, payload: &[u8]) -> bool {
            !message_name.is_empty() && !payload.is_empty()
        }
    }
    impl SchedulerEnvelopeFactoryPort for ContractProbe {
        fn envelope(&self, schedule_id: &str, occurrence: u64) -> Option<Vec<u8>> {
            (!schedule_id.is_empty()).then(|| occurrence.to_be_bytes().to_vec())
        }
    }
    impl RealtimeFanoutAuthorizerPort for ContractProbe {
        fn authorizes_fanout(&self, subject: &str, topic: &str) -> bool {
            !subject.is_empty() && !topic.is_empty()
        }
    }
    impl RealtimeIdentityRevalidatorPort for ContractProbe {
        fn identity_is_live(&self, subject: &str) -> bool {
            !subject.is_empty()
        }
    }
    impl RealtimeEventHandlerPort for ContractProbe {
        fn handle_event(&self, event_name: &str, payload: &[u8]) -> bool {
            !event_name.is_empty() && !payload.is_empty()
        }
    }
    impl UploadWorkflowPort for ContractProbe {
        fn advance(&self, upload_id: &str, transition: &str) -> bool {
            !upload_id.is_empty() && !transition.is_empty()
        }
    }
    impl UploadAuthorizationPort for ContractProbe {
        fn authorizes_upload(&self, subject: &str, upload_id: &str, operation: &str) -> bool {
            !subject.is_empty() && !upload_id.is_empty() && !operation.is_empty()
        }
    }
    impl WebhooksSvixReplayAdmissionPort for ContractProbe {
        fn admit_replay(&self, event_id: &str) -> bool {
            !event_id.is_empty()
        }
    }
    impl WebhooksInboundProviderAdaptersPort for ContractProbe {
        fn supports_provider(&self, provider: &str) -> bool {
            !provider.is_empty()
        }
    }
    impl WebhooksInboundHandlersPort for ContractProbe {
        fn handle_webhook(&self, provider: &str, event_id: &str, payload: &[u8]) -> bool {
            !provider.is_empty() && !event_id.is_empty() && !payload.is_empty()
        }
    }
    impl FeatureFlagProviderPort for ContractProbe {
        fn enabled(&self, flag: &str, subject: &str) -> bool {
            !flag.is_empty() && !subject.is_empty()
        }
    }
    impl FeatureFlagExposureRecorderPort for ContractProbe {
        fn record_exposure(&self, flag: &str, subject: &str, _enabled: bool) -> bool {
            !flag.is_empty() && !subject.is_empty()
        }
    }
    impl SearchIndexSchemaPort for ContractProbe {
        fn schema_digest(&self, index: &str) -> Option<String> {
            (!index.is_empty()).then(|| "digest".to_owned())
        }
    }
    impl SearchReauthorizerPort for ContractProbe {
        fn reauthorize(&self, subject: &str, source_id: &str) -> bool {
            !subject.is_empty() && !source_id.is_empty()
        }
    }
    impl SearchProjectionResolverPort for ContractProbe {
        fn projection(&self, source_id: &str) -> Option<Vec<u8>> {
            (!source_id.is_empty()).then(|| source_id.as_bytes().to_vec())
        }
    }
    impl BillingProviderPort for ContractProbe {
        fn execute_billing(&self, account_id: &str, operation: &str) -> bool {
            !account_id.is_empty() && !operation.is_empty()
        }
    }
    impl GraphqlSchemaPort for ContractProbe {
        fn declares_field(&self, field: &str) -> bool {
            !field.is_empty()
        }
    }
    impl GraphqlRequestDataInjectorPort for ContractProbe {
        fn inject_request_data(&self, subject: &str) -> bool {
            !subject.is_empty()
        }
    }
    impl GrpcApplicationServicePort for ContractProbe {
        fn execute_method(&self, method: &str, payload: &[u8]) -> bool {
            !method.is_empty() && !payload.is_empty()
        }
    }
    impl GrpcAuthenticatorPort for ContractProbe {
        fn authenticate_metadata(&self, authorization: &str) -> Option<String> {
            (!authorization.is_empty()).then(|| "subject".to_owned())
        }
    }
    impl GrpcMethodPoliciesPort for ContractProbe {
        fn authorizes_method(&self, subject: &str, method: &str) -> bool {
            !subject.is_empty() && !method.is_empty()
        }
    }
    impl PrivacyInventoryManifestPort for ContractProbe {
        fn manifest_digest(&self) -> String {
            "manifest-digest".to_owned()
        }
    }
    impl PrivacyInventoryAdaptersPort for ContractProbe {
        fn inventory(&self, data_class: &str) -> Option<Vec<u8>> {
            (!data_class.is_empty()).then(|| data_class.as_bytes().to_vec())
        }
    }
    impl PrivacyAuthorizerPort for ContractProbe {
        fn authorizes_privacy(&self, subject: &str, operation: &str) -> bool {
            !subject.is_empty() && !operation.is_empty()
        }
    }
    impl PrivacyLifecycleHandlerPort for ContractProbe {
        fn execute_lifecycle(&self, request_id: &str, operation: &str) -> bool {
            !request_id.is_empty() && !operation.is_empty()
        }
    }
    impl PrivacyConsentPolicyPort for ContractProbe {
        fn has_consent(&self, subject: &str, purpose: &str) -> bool {
            !subject.is_empty() && !purpose.is_empty()
        }
    }
    impl PrivacyModerationPolicyPort for ContractProbe {
        fn permits_content(&self, subject: &str, content: &[u8]) -> bool {
            !subject.is_empty() && !content.is_empty()
        }
    }
    impl LlmToolAuthorizationPort for ContractProbe {
        fn authorizes_tool(&self, subject: &str, tool: &str) -> bool {
            !subject.is_empty() && !tool.is_empty()
        }
    }
    impl LlmToolAuditPort for ContractProbe {
        fn record_tool_outcome(&self, invocation_id: &str, _succeeded: bool) -> bool {
            !invocation_id.is_empty()
        }
    }
    impl LlmMediaScannerPort for ContractProbe {
        fn scans_clean(&self, media_id: &str, bytes: &[u8]) -> bool {
            !media_id.is_empty() && !bytes.is_empty()
        }
    }
    impl LlmMediaAuthorizationPort for ContractProbe {
        fn authorizes_media(&self, subject: &str, media_id: &str, operation: &str) -> bool {
            !subject.is_empty() && !media_id.is_empty() && !operation.is_empty()
        }
    }
    impl LlmEvaluationRepositoryPort for ContractProbe {
        fn store_evaluation(&self, evaluation_id: &str, report: &[u8]) -> bool {
            !evaluation_id.is_empty() && !report.is_empty()
        }
    }
    impl McpCapabilityRegistryPort for ContractProbe {
        fn contains_capability(&self, capability: &str) -> bool {
            !capability.is_empty()
        }
    }
    impl McpBearerAuthenticatorPort for ContractProbe {
        fn authenticate_bearer(&self, credential: &str) -> Option<String> {
            (!credential.is_empty()).then(|| "subject".to_owned())
        }
    }
    impl McpEnterprisePorts for ContractProbe {
        fn authorizes_enterprise(&self, subject: &str, operation: &str) -> bool {
            !subject.is_empty() && !operation.is_empty()
        }
    }
    impl McpSubscriptionRepositoryPort for ContractProbe {
        fn store_subscription(&self, subscription_id: &str) -> bool {
            !subscription_id.is_empty()
        }
    }
    impl McpSubscriptionAuthorizerPort for ContractProbe {
        fn authorizes_subscription(&self, subject: &str, task_id: &str) -> bool {
            !subject.is_empty() && !task_id.is_empty()
        }
    }
    impl McpSubscriptionRuntimePort for ContractProbe {
        fn arm_subscription(&self, subscription_id: &str) -> bool {
            !subscription_id.is_empty()
        }
    }
    impl McpSubscriptionDeliveryPort for ContractProbe {
        fn deliver_subscription(&self, subscription_id: &str, frame: &[u8]) -> bool {
            !subscription_id.is_empty() && !frame.is_empty()
        }
    }
    impl McpTaskPayloadProtectorPort for ContractProbe {
        fn seal_payload(&self, task_id: &str, payload: &[u8]) -> Option<Vec<u8>> {
            (!task_id.is_empty() && !payload.is_empty()).then(|| payload.to_vec())
        }
    }
    impl McpCancellationRuntimePort for ContractProbe {
        fn cancel_task(&self, task_id: &str) -> bool {
            !task_id.is_empty()
        }
    }
    impl McpCapabilityExecutorPort for ContractProbe {
        fn execute_capability(&self, capability: &str, payload: &[u8]) -> bool {
            !capability.is_empty() && !payload.is_empty()
        }
    }
    impl McpAppsPorts for ContractProbe {
        fn admit_app_action(&self, app_id: &str, action: &str) -> bool {
            !app_id.is_empty() && !action.is_empty()
        }
    }

    fn present_admin_auth(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::AdminAuthorityResolver => ApplicationContributions::new()
                .with_admin_runtime(AdminRuntime::default().with_authority_resolver(probe)),
            ApplicationRequirement::AdminOperationHandler => ApplicationContributions::new()
                .with_admin_runtime(AdminRuntime::default().with_operation_handler(probe)),
            ApplicationRequirement::AuthAuthenticatedRuntime => ApplicationContributions::new()
                .with_auth_runtime(AuthRuntime::default().with_authenticated_runtime(probe)),
            ApplicationRequirement::AuthRedisSessionRuntime => ApplicationContributions::new()
                .with_auth_runtime(AuthRuntime::default().with_redis_session_runtime(probe)),
            ApplicationRequirement::AuthOidcRuntime => ApplicationContributions::new()
                .with_auth_runtime(AuthRuntime::default().with_oidc_runtime(probe)),
            ApplicationRequirement::AuthOauthRuntime => ApplicationContributions::new()
                .with_auth_runtime(AuthRuntime::default().with_oauth_runtime(probe)),
            ApplicationRequirement::AuthWebAuthnRuntime => ApplicationContributions::new()
                .with_auth_runtime(AuthRuntime::default().with_webauthn_runtime(probe)),
            ApplicationRequirement::AuthTotpRuntime => ApplicationContributions::new()
                .with_auth_runtime(AuthRuntime::default().with_totp_runtime(probe)),
            _ => unreachable!("admin/auth requirement family dispatch must be exact"),
        }
    }

    fn present_service(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::BillingProvider => ApplicationContributions::new()
                .with_billing_runtime(BillingRuntime::default().with_provider(probe)),
            ApplicationRequirement::FeatureFlagsExposureRecorder => ApplicationContributions::new()
                .with_feature_flags_runtime(
                    FeatureFlagsRuntime::default().with_exposure_recorder(probe),
                ),
            ApplicationRequirement::FeatureFlagsProvider => ApplicationContributions::new()
                .with_feature_flags_runtime(FeatureFlagsRuntime::default().with_provider(probe)),
            ApplicationRequirement::GraphqlRequestDataInjector => ApplicationContributions::new()
                .with_graphql_runtime(GraphqlRuntime::default().with_request_data_injector(probe)),
            ApplicationRequirement::GraphqlSchema => ApplicationContributions::new()
                .with_graphql_runtime(GraphqlRuntime::default().with_schema(probe)),
            ApplicationRequirement::GrpcApplicationService => ApplicationContributions::new()
                .with_grpc_runtime(GrpcRuntime::default().with_application_service(probe)),
            ApplicationRequirement::GrpcAuthenticator => ApplicationContributions::new()
                .with_grpc_runtime(GrpcRuntime::default().with_authenticator(probe)),
            ApplicationRequirement::GrpcMethodPolicies => ApplicationContributions::new()
                .with_grpc_runtime(GrpcRuntime::default().with_method_policies(probe)),
            ApplicationRequirement::InboxConsumers => ApplicationContributions::new()
                .with_inbox_runtime(InboxRuntime::default().with_consumers(probe)),
            ApplicationRequirement::JobsHandlers => ApplicationContributions::new()
                .with_jobs_runtime(JobsRuntime::default().with_handlers(probe)),
            _ => unreachable!("service requirement family dispatch must be exact"),
        }
    }

    fn present_llm(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::LlmEvaluationRepository => ApplicationContributions::new()
                .with_llm_runtime(LlmRuntime::default().with_evaluation_repository(probe)),
            ApplicationRequirement::LlmMediaAuthorization => ApplicationContributions::new()
                .with_llm_runtime(LlmRuntime::default().with_media_authorization(probe)),
            ApplicationRequirement::LlmMediaScanner => ApplicationContributions::new()
                .with_llm_runtime(LlmRuntime::default().with_media_scanner(probe)),
            ApplicationRequirement::LlmToolAudit => ApplicationContributions::new()
                .with_llm_runtime(LlmRuntime::default().with_tool_audit(probe)),
            ApplicationRequirement::LlmToolAuthorization => ApplicationContributions::new()
                .with_llm_runtime(LlmRuntime::default().with_tool_authorization(probe)),
            _ => unreachable!("LLM requirement family dispatch must be exact"),
        }
    }

    fn present_mcp_core(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::McpAppsPorts => ApplicationContributions::new()
                .with_mcp_apps_runtime(McpAppsRuntime::default().with_ports(probe)),
            ApplicationRequirement::McpBearerAuthenticator => ApplicationContributions::new()
                .with_mcp_auth_runtime(McpAuthRuntime::default().with_bearer_authenticator(probe)),
            ApplicationRequirement::McpCancellationRuntime => ApplicationContributions::new()
                .with_mcp_tasks_runtime(
                    McpTasksRuntime::default().with_cancellation_runtime(probe),
                ),
            ApplicationRequirement::McpCapabilityExecutor => ApplicationContributions::new()
                .with_mcp_tasks_runtime(McpTasksRuntime::default().with_capability_executor(probe)),
            ApplicationRequirement::McpCapabilityRegistry => ApplicationContributions::new()
                .with_mcp_core_runtime(McpCoreRuntime::default().with_capability_registry(probe)),
            ApplicationRequirement::McpEnterprisePorts => ApplicationContributions::new()
                .with_mcp_enterprise_runtime(McpEnterpriseRuntime::default().with_ports(probe)),
            _ => unreachable!("MCP core requirement family dispatch must be exact"),
        }
    }

    fn present_mcp_work(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::McpSubscriptionAuthorizer => ApplicationContributions::new()
                .with_mcp_subscriptions_runtime(
                    McpSubscriptionsRuntime::default().with_authorizer(probe),
                ),
            ApplicationRequirement::McpSubscriptionDelivery => ApplicationContributions::new()
                .with_mcp_subscriptions_runtime(
                    McpSubscriptionsRuntime::default().with_delivery(probe),
                ),
            ApplicationRequirement::McpSubscriptionRepository => ApplicationContributions::new()
                .with_mcp_subscriptions_runtime(
                    McpSubscriptionsRuntime::default().with_repository(probe),
                ),
            ApplicationRequirement::McpSubscriptionRuntime => ApplicationContributions::new()
                .with_mcp_subscriptions_runtime(
                    McpSubscriptionsRuntime::default().with_runtime(probe),
                ),
            ApplicationRequirement::McpTaskPayloadProtector => ApplicationContributions::new()
                .with_mcp_tasks_runtime(McpTasksRuntime::default().with_payload_protector(probe)),
            _ => unreachable!("MCP work requirement family dispatch must be exact"),
        }
    }

    fn present_data(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::OutboxPublisher => ApplicationContributions::new()
                .with_outbox_runtime(OutboxRuntime::default().with_publisher(probe)),
            ApplicationRequirement::PrivacyAuthorizer => ApplicationContributions::new()
                .with_privacy_runtime(PrivacyRuntime::default().with_authorizer(probe)),
            ApplicationRequirement::PrivacyConsentPolicy => ApplicationContributions::new()
                .with_privacy_runtime(PrivacyRuntime::default().with_consent_policy(probe)),
            ApplicationRequirement::PrivacyInventoryAdapters => ApplicationContributions::new()
                .with_privacy_runtime(PrivacyRuntime::default().with_inventory_adapters(probe)),
            ApplicationRequirement::PrivacyInventoryManifest => ApplicationContributions::new()
                .with_privacy_runtime(PrivacyRuntime::default().with_inventory_manifest(probe)),
            ApplicationRequirement::PrivacyLifecycleHandler => ApplicationContributions::new()
                .with_privacy_runtime(PrivacyRuntime::default().with_lifecycle_handler(probe)),
            ApplicationRequirement::PrivacyModerationPolicy => ApplicationContributions::new()
                .with_privacy_runtime(PrivacyRuntime::default().with_moderation_policy(probe)),
            _ => unreachable!("data requirement family dispatch must be exact"),
        }
    }

    fn present_delivery(
        requirement: ApplicationRequirement,
        probe: Arc<ContractProbe>,
    ) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::RealtimeEventHandler => ApplicationContributions::new()
                .with_realtime_runtime(RealtimeRuntime::default().with_event_handler(probe)),
            ApplicationRequirement::RealtimeFanoutAuthorizer => ApplicationContributions::new()
                .with_realtime_runtime(RealtimeRuntime::default().with_fanout_authorizer(probe)),
            ApplicationRequirement::RealtimeIdentityRevalidator => ApplicationContributions::new()
                .with_realtime_runtime(RealtimeRuntime::default().with_identity_revalidator(probe)),
            ApplicationRequirement::SchedulerEnvelopeFactory => ApplicationContributions::new()
                .with_scheduler_runtime(SchedulerRuntime::default().with_envelope_factory(probe)),
            ApplicationRequirement::SearchIndexSchema => ApplicationContributions::new()
                .with_search_runtime(SearchRuntime::default().with_index_schema(probe)),
            ApplicationRequirement::SearchProjectionResolver => ApplicationContributions::new()
                .with_search_runtime(SearchRuntime::default().with_projection_resolver(probe)),
            ApplicationRequirement::SearchReauthorizer => ApplicationContributions::new()
                .with_search_runtime(SearchRuntime::default().with_reauthorizer(probe)),
            ApplicationRequirement::UploadsAuthorization => ApplicationContributions::new()
                .with_uploads_runtime(UploadsRuntime::default().with_authorization(probe)),
            ApplicationRequirement::UploadsWorkflow => ApplicationContributions::new()
                .with_uploads_runtime(UploadsRuntime::default().with_workflow(probe)),
            ApplicationRequirement::WebhooksInboundHandlers => ApplicationContributions::new()
                .with_webhooks_inbound_runtime(
                    WebhooksInboundRuntime::default().with_handlers(probe),
                ),
            ApplicationRequirement::WebhooksInboundProviderAdapters => {
                ApplicationContributions::new().with_webhooks_inbound_runtime(
                    WebhooksInboundRuntime::default().with_provider_adapters(probe),
                )
            }
            ApplicationRequirement::WebhooksSvixReplayAdmission => ApplicationContributions::new()
                .with_webhooks_svix_runtime(
                    WebhooksSvixRuntime::default().with_replay_admission(probe),
                ),
            _ => unreachable!("delivery requirement family dispatch must be exact"),
        }
    }

    fn present(requirement: ApplicationRequirement) -> ApplicationContributions {
        let probe = Arc::new(ContractProbe);
        match requirement {
            ApplicationRequirement::AdminAuthorityResolver
            | ApplicationRequirement::AdminOperationHandler
            | ApplicationRequirement::AuthAuthenticatedRuntime
            | ApplicationRequirement::AuthRedisSessionRuntime
            | ApplicationRequirement::AuthOidcRuntime
            | ApplicationRequirement::AuthOauthRuntime
            | ApplicationRequirement::AuthWebAuthnRuntime
            | ApplicationRequirement::AuthTotpRuntime => present_admin_auth(requirement, probe),
            ApplicationRequirement::BillingProvider
            | ApplicationRequirement::FeatureFlagsExposureRecorder
            | ApplicationRequirement::FeatureFlagsProvider
            | ApplicationRequirement::GraphqlRequestDataInjector
            | ApplicationRequirement::GraphqlSchema
            | ApplicationRequirement::GrpcApplicationService
            | ApplicationRequirement::GrpcAuthenticator
            | ApplicationRequirement::GrpcMethodPolicies
            | ApplicationRequirement::InboxConsumers
            | ApplicationRequirement::JobsHandlers => present_service(requirement, probe),
            ApplicationRequirement::LlmEvaluationRepository
            | ApplicationRequirement::LlmMediaAuthorization
            | ApplicationRequirement::LlmMediaScanner
            | ApplicationRequirement::LlmToolAudit
            | ApplicationRequirement::LlmToolAuthorization => present_llm(requirement, probe),
            ApplicationRequirement::McpAppsPorts
            | ApplicationRequirement::McpBearerAuthenticator
            | ApplicationRequirement::McpCancellationRuntime
            | ApplicationRequirement::McpCapabilityExecutor
            | ApplicationRequirement::McpCapabilityRegistry
            | ApplicationRequirement::McpEnterprisePorts => present_mcp_core(requirement, probe),
            ApplicationRequirement::McpSubscriptionAuthorizer
            | ApplicationRequirement::McpSubscriptionDelivery
            | ApplicationRequirement::McpSubscriptionRepository
            | ApplicationRequirement::McpSubscriptionRuntime
            | ApplicationRequirement::McpTaskPayloadProtector => {
                present_mcp_work(requirement, probe)
            }
            ApplicationRequirement::OutboxPublisher
            | ApplicationRequirement::PrivacyAuthorizer
            | ApplicationRequirement::PrivacyConsentPolicy
            | ApplicationRequirement::PrivacyInventoryAdapters
            | ApplicationRequirement::PrivacyInventoryManifest
            | ApplicationRequirement::PrivacyLifecycleHandler
            | ApplicationRequirement::PrivacyModerationPolicy => present_data(requirement, probe),
            ApplicationRequirement::RealtimeEventHandler
            | ApplicationRequirement::RealtimeFanoutAuthorizer
            | ApplicationRequirement::RealtimeIdentityRevalidator
            | ApplicationRequirement::SchedulerEnvelopeFactory
            | ApplicationRequirement::SearchIndexSchema
            | ApplicationRequirement::SearchProjectionResolver
            | ApplicationRequirement::SearchReauthorizer
            | ApplicationRequirement::UploadsAuthorization
            | ApplicationRequirement::UploadsWorkflow
            | ApplicationRequirement::WebhooksInboundHandlers
            | ApplicationRequirement::WebhooksInboundProviderAdapters
            | ApplicationRequirement::WebhooksSvixReplayAdmission => {
                present_delivery(requirement, probe)
            }
        }
    }

    fn malformed(requirement: ApplicationRequirement) -> ApplicationContributions {
        match requirement {
            ApplicationRequirement::AdminAuthorityResolver
            | ApplicationRequirement::AdminOperationHandler => {
                ApplicationContributions::new().with_admin_runtime(AdminRuntime::default())
            }
            ApplicationRequirement::AuthAuthenticatedRuntime
            | ApplicationRequirement::AuthRedisSessionRuntime
            | ApplicationRequirement::AuthOidcRuntime
            | ApplicationRequirement::AuthOauthRuntime
            | ApplicationRequirement::AuthWebAuthnRuntime
            | ApplicationRequirement::AuthTotpRuntime => {
                ApplicationContributions::new().with_auth_runtime(AuthRuntime::default())
            }
            ApplicationRequirement::BillingProvider => {
                ApplicationContributions::new().with_billing_runtime(BillingRuntime::default())
            }
            ApplicationRequirement::FeatureFlagsExposureRecorder
            | ApplicationRequirement::FeatureFlagsProvider => ApplicationContributions::new()
                .with_feature_flags_runtime(FeatureFlagsRuntime::default()),
            ApplicationRequirement::GraphqlRequestDataInjector
            | ApplicationRequirement::GraphqlSchema => {
                ApplicationContributions::new().with_graphql_runtime(GraphqlRuntime::default())
            }
            ApplicationRequirement::GrpcApplicationService
            | ApplicationRequirement::GrpcAuthenticator
            | ApplicationRequirement::GrpcMethodPolicies => {
                ApplicationContributions::new().with_grpc_runtime(GrpcRuntime::default())
            }
            ApplicationRequirement::InboxConsumers => {
                ApplicationContributions::new().with_inbox_runtime(InboxRuntime::default())
            }
            ApplicationRequirement::JobsHandlers => {
                ApplicationContributions::new().with_jobs_runtime(JobsRuntime::default())
            }
            ApplicationRequirement::LlmEvaluationRepository
            | ApplicationRequirement::LlmMediaAuthorization
            | ApplicationRequirement::LlmMediaScanner
            | ApplicationRequirement::LlmToolAudit
            | ApplicationRequirement::LlmToolAuthorization => {
                ApplicationContributions::new().with_llm_runtime(LlmRuntime::default())
            }
            ApplicationRequirement::McpAppsPorts => {
                ApplicationContributions::new().with_mcp_apps_runtime(McpAppsRuntime::default())
            }
            ApplicationRequirement::McpBearerAuthenticator => {
                ApplicationContributions::new().with_mcp_auth_runtime(McpAuthRuntime::default())
            }
            ApplicationRequirement::McpCapabilityRegistry => {
                ApplicationContributions::new().with_mcp_core_runtime(McpCoreRuntime::default())
            }
            ApplicationRequirement::McpEnterprisePorts => ApplicationContributions::new()
                .with_mcp_enterprise_runtime(McpEnterpriseRuntime::default()),
            ApplicationRequirement::McpSubscriptionAuthorizer
            | ApplicationRequirement::McpSubscriptionDelivery
            | ApplicationRequirement::McpSubscriptionRepository
            | ApplicationRequirement::McpSubscriptionRuntime => ApplicationContributions::new()
                .with_mcp_subscriptions_runtime(McpSubscriptionsRuntime::default()),
            ApplicationRequirement::McpCancellationRuntime
            | ApplicationRequirement::McpCapabilityExecutor
            | ApplicationRequirement::McpTaskPayloadProtector => {
                ApplicationContributions::new().with_mcp_tasks_runtime(McpTasksRuntime::default())
            }
            ApplicationRequirement::OutboxPublisher => {
                ApplicationContributions::new().with_outbox_runtime(OutboxRuntime::default())
            }
            ApplicationRequirement::PrivacyAuthorizer
            | ApplicationRequirement::PrivacyConsentPolicy
            | ApplicationRequirement::PrivacyInventoryAdapters
            | ApplicationRequirement::PrivacyInventoryManifest
            | ApplicationRequirement::PrivacyLifecycleHandler
            | ApplicationRequirement::PrivacyModerationPolicy => {
                ApplicationContributions::new().with_privacy_runtime(PrivacyRuntime::default())
            }
            ApplicationRequirement::RealtimeEventHandler
            | ApplicationRequirement::RealtimeFanoutAuthorizer
            | ApplicationRequirement::RealtimeIdentityRevalidator => {
                ApplicationContributions::new().with_realtime_runtime(RealtimeRuntime::default())
            }
            ApplicationRequirement::SchedulerEnvelopeFactory => {
                ApplicationContributions::new().with_scheduler_runtime(SchedulerRuntime::default())
            }
            ApplicationRequirement::SearchIndexSchema
            | ApplicationRequirement::SearchProjectionResolver
            | ApplicationRequirement::SearchReauthorizer => {
                ApplicationContributions::new().with_search_runtime(SearchRuntime::default())
            }
            ApplicationRequirement::UploadsAuthorization
            | ApplicationRequirement::UploadsWorkflow => {
                ApplicationContributions::new().with_uploads_runtime(UploadsRuntime::default())
            }
            ApplicationRequirement::WebhooksInboundHandlers
            | ApplicationRequirement::WebhooksInboundProviderAdapters => {
                ApplicationContributions::new()
                    .with_webhooks_inbound_runtime(WebhooksInboundRuntime::default())
            }
            ApplicationRequirement::WebhooksSvixReplayAdmission => ApplicationContributions::new()
                .with_webhooks_svix_runtime(WebhooksSvixRuntime::default()),
        }
    }

    fn input(
        contracts: &'static [SelectedModuleContract],
        disabled: &'static [&'static str],
    ) -> CompositionInput {
        CompositionInput {
            profile: "contract-test",
            modules: &["contract-test-module"],
            providers: &[],
            contracts,
            runtime_disabled_modules: disabled,
        }
    }

    #[test]
    fn every_requirement_has_one_typed_present_missing_and_malformed_path() {
        for requirement in ApplicationRequirement::ALL {
            let mut missing = ApplicationContributions::new();
            let missing_builder = AppCompositionBuilder::new(input(&[], &[]), &mut missing);
            assert_eq!(
                missing_builder.require("contract-test-module", *requirement),
                Err(CompositionError::MissingContribution {
                    module: "contract-test-module",
                    contribution: requirement.as_str(),
                })
            );

            let mut supplied = present(*requirement);
            let supplied_builder = AppCompositionBuilder::new(input(&[], &[]), &mut supplied);
            assert_eq!(
                supplied_builder.require("contract-test-module", *requirement),
                Ok(())
            );

            let mut grouped = malformed(*requirement);
            let grouped_builder = AppCompositionBuilder::new(input(&[], &[]), &mut grouped);
            assert_eq!(
                grouped_builder.require("contract-test-module", *requirement),
                Err(CompositionError::ContractMismatch {
                    kind: "application-requirement",
                    id: requirement.as_str(),
                })
            );
        }
    }

    #[test]
    fn disabled_runtime_toggles_skip_every_dormant_requirement() {
        const CONTRACTS: &[SelectedModuleContract] = &[SelectedModuleContract {
            module: "contract-test-module",
            runtime_toggle: true,
            routes: &[],
            tasks: &[],
            health_checks: &[],
            application_requirements: ApplicationRequirement::ALL,
        }];
        let mut contributions = ApplicationContributions::new();
        let builder = AppCompositionBuilder::new(
            input(CONTRACTS, &["contract-test-module"]),
            &mut contributions,
        );
        assert_eq!(builder.finish().map(|_| ()), Ok(()));
    }
    #[cfg(feature = "postgres")]
    #[test]
    fn application_runtime_reports_a_missing_postgres_pool() {
        assert!(matches!(
            ApplicationRuntime::default().postgres_pool(),
            Err(ApplicationExtensionError::MissingPostgresPool)
        ));
    }

    #[cfg(feature = "idempotency")]
    #[test]
    fn application_runtime_reports_a_missing_idempotency_store() {
        assert!(matches!(
            ApplicationRuntime::default().idempotency_store(),
            Err(ApplicationExtensionError::MissingIdempotencyStore)
        ));
    }

    #[cfg(feature = "http")]
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    #[cfg(feature = "http")]
    use tower::ServiceExt as _;

    #[cfg(feature = "http")]
    const APPLICATION_ROUTES: &[&str] = &["/application"];
    #[cfg(feature = "http")]
    const APPLICATION_OPERATIONS: &[ExpectedOperation] = &[ExpectedOperation::new(
        "get",
        "/application",
        "getApplication",
        "application",
    )];
    #[cfg(feature = "openapi")]
    const OPENAPI_CONTRACTS: &[SelectedModuleContract] = &[SelectedModuleContract {
        module: "openapi",
        runtime_toggle: true,
        routes: &["/openapi.json", "/docs"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    }];

    #[cfg(feature = "http")]
    fn application_document() -> serde_json::Value {
        serde_json::json!({
            "openapi": "3.1.0",
            "info": {"title": "application", "version": "1.0.0"},
            "paths": {
                "/application": {
                    "get": {
                        "operationId": "getApplication",
                        "tags": ["application"],
                        "security": [],
                        "responses": {
                            "204": {"description": "application"},
                            "400": {
                                "description": "invalid request",
                                "content": {
                                    "application/problem+json": {
                                        "schema": {
                                            "type": "object",
                                            "required": [
                                                "type",
                                                "title",
                                                "status",
                                                "code",
                                                "request_id"
                                            ],
                                            "properties": {
                                                "type": {"type": "string"},
                                                "title": {"type": "string"},
                                                "status": {"type": "integer"},
                                                "code": {"type": "string"},
                                                "request_id": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[cfg(feature = "http")]
    fn application_extension() -> ApplicationExtension {
        ApplicationExtension::new(
            Router::new().route("/application", get(|| async { StatusCode::NO_CONTENT })),
            APPLICATION_ROUTES,
            application_document(),
            APPLICATION_OPERATIONS,
        )
    }

    #[cfg(feature = "http")]
    fn resolved_application_contributions()
    -> Result<ApplicationContributions, ApplicationExtensionError> {
        ApplicationContributions::new()
            .with_application_extension(|_| Ok(application_extension()))
            .with_selected_runtime(SelectedRuntime::default())
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_finalization_requires_an_application_extension() {
        let mut contributions = ApplicationContributions::new();
        let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);

        assert_eq!(
            modules::http::finalize(&mut builder),
            Err(CompositionError::MissingContribution {
                module: "http",
                contribution: "application.extension",
            })
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn application_extension_factory_is_last_wins_and_one_shot() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let first_factory_calls = Arc::clone(&first_calls);
        let second_factory_calls = Arc::clone(&second_calls);
        let contributions = ApplicationContributions::new()
            .with_application_extension(move |_| {
                first_factory_calls.fetch_add(1, Ordering::Relaxed);
                Ok(application_extension())
            })
            .with_application_extension(move |_| {
                second_factory_calls.fetch_add(1, Ordering::Relaxed);
                Ok(application_extension())
            })
            .with_selected_runtime(SelectedRuntime::default())
            .and_then(|contributions| {
                contributions.with_selected_runtime(SelectedRuntime::default())
            });

        assert!(contributions.is_ok());
        assert_eq!(
            (
                first_calls.load(Ordering::Relaxed),
                second_calls.load(Ordering::Relaxed)
            ),
            (0, 1)
        );
    }

    #[cfg(all(feature = "http", feature = "idempotency"))]
    #[test]
    fn application_extension_factory_receives_selected_resources() -> Result<(), Box<dyn Error>> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let received = Arc::new(AtomicBool::new(false));
        let factory_received = Arc::clone(&received);
        let store = omnius_idempotency::PostgresIdempotencyStore::new(
            omnius_idempotency::IdempotencyConfig::default(),
        )?;
        let runtime = SelectedRuntime {
            idempotency_store: Some(store),
            ..SelectedRuntime::default()
        };

        let _contributions = ApplicationContributions::new()
            .with_application_extension(move |runtime| {
                let _store = runtime.idempotency_store()?;
                factory_received.store(true, Ordering::Relaxed);
                Ok(application_extension())
            })
            .with_selected_runtime(runtime)?;

        assert!(received.load(Ordering::Relaxed));
        Ok(())
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn http_finalization_mounts_the_application_router_once() -> Result<(), Box<dyn Error>> {
        let mut contributions = resolved_application_contributions()?;
        let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
        modules::http::finalize(&mut builder)?;
        let second = modules::http::finalize(&mut builder);
        let router = builder.finish()?.into_runtime_parts().0;
        let response = router
            .oneshot(Request::get("/application").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            second,
            Err(CompositionError::MissingContribution {
                module: "http",
                contribution: "application.extension",
            })
        );
        Ok(())
    }

    #[cfg(all(feature = "http", not(feature = "openapi")))]
    #[tokio::test]
    async fn http_mounts_the_application_when_openapi_is_not_compiled() -> Result<(), Box<dyn Error>>
    {
        let mut contributions = resolved_application_contributions()?;
        let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
        modules::http::finalize(&mut builder)?;
        let router = builder.finish()?.into_runtime_parts().0;
        let response = router
            .oneshot(Request::get("/application").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[cfg(all(feature = "http", feature = "rate-limit-local"))]
    #[tokio::test]
    async fn http_finalization_applies_the_recorded_local_limiter() -> Result<(), Box<dyn Error>> {
        let mut contributions = ApplicationContributions::new()
            .with_application_rate_limit(ApplicationRateLimitConfig {
                enabled: true,
                replenish_every: Duration::from_secs(60),
                burst_size: 1,
                identity_buckets: 16,
            })
            .with_application_extension(|_| Ok(application_extension()))
            .with_selected_runtime(SelectedRuntime::default())?;
        let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
        modules::rate_limit_local::register(&mut builder)?;
        modules::http::finalize(&mut builder)?;
        let router = builder.finish()?.into_runtime_parts().0;
        let request = || {
            let mut request = Request::get("/application").body(Body::empty())?;
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            ));
            request
                .extensions_mut()
                .insert(omnius_core::RequestId::new());
            Ok::<_, axum::http::Error>(request)
        };
        let first = router.clone().oneshot(request()?).await?;
        let second = router.oneshot(request()?).await?;

        assert_eq!(
            (first.status(), second.status()),
            (StatusCode::NO_CONTENT, StatusCode::TOO_MANY_REQUESTS)
        );
        Ok(())
    }

    #[cfg(all(feature = "openapi", not(feature = "idempotency")))]
    #[tokio::test]
    async fn openapi_installs_from_the_extension_without_idempotency() -> Result<(), Box<dyn Error>>
    {
        let runtime = SelectedRuntime {
            openapi_config: Some(omnius_openapi::OpenApiConfig::default()),
            ..SelectedRuntime::default()
        };
        let mut contributions = ApplicationContributions::new()
            .with_application_extension(|_| Ok(application_extension()))
            .with_selected_runtime(runtime)?;
        let mut builder =
            AppCompositionBuilder::new(input(OPENAPI_CONTRACTS, &[]), &mut contributions);
        modules::http::finalize(&mut builder)?;
        let application = builder.finish()?;
        assert!(application.public_operations().contains("getApplication"));
        let router = application.into_runtime_parts().0;
        let response = router
            .oneshot(Request::get("/openapi.json").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[cfg(feature = "openapi")]
    #[test]
    fn extension_document_must_cover_its_declared_operations() {
        const MISMATCHED: &[ExpectedOperation] = &[ExpectedOperation::new(
            "get",
            "/application",
            "renamedApplication",
            "application",
        )];

        let runtime = SelectedRuntime {
            openapi_config: Some(omnius_openapi::OpenApiConfig::default()),
            ..SelectedRuntime::default()
        };
        let contributions = ApplicationContributions::new()
            .with_application_extension(|_| {
                Ok(ApplicationExtension::new(
                    Router::new(),
                    APPLICATION_ROUTES,
                    application_document(),
                    MISMATCHED,
                ))
            })
            .with_selected_runtime(runtime);
        let Ok(mut contributions) = contributions else {
            panic!("application extension factory must succeed");
        };
        let mut builder =
            AppCompositionBuilder::new(input(OPENAPI_CONTRACTS, &[]), &mut contributions);

        assert_eq!(
            modules::http::finalize(&mut builder),
            Err(CompositionError::InvalidConfiguration { module: "openapi" })
        );
    }

    #[cfg(all(feature = "http", feature = "idempotency"))]
    #[tokio::test]
    async fn idempotency_registers_only_its_store_and_no_reference_routes()
    -> Result<(), Box<dyn Error>> {
        let store = omnius_idempotency::PostgresIdempotencyStore::new(
            omnius_idempotency::IdempotencyConfig::default(),
        )?;
        let runtime = SelectedRuntime {
            idempotency_store: Some(store),
            ..SelectedRuntime::default()
        };
        let mut contributions = ApplicationContributions::new()
            .with_application_extension(|_| Ok(application_extension()))
            .with_selected_runtime(runtime)?;
        let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
        modules::idempotency::register(&mut builder)?;
        modules::http::finalize(&mut builder)?;
        let router = builder.finish()?.into_runtime_parts().0;
        let response = router
            .oneshot(Request::get("/reference-records").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}
