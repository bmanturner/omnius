//! Static application composition for generated services.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};

use axum::Router;
use omnius_health::HealthCheckSpec;
use omnius_runtime::{Criticality, TaskSpec};
use serde::{Deserialize, Serialize};

pub use omnius_core::{
    BuildMetadata, BuildMetadataInput, InvalidBuildMetadata, ProviderMetadata, SchemaCompatibility,
};

mod modules;
mod selected;
pub use selected::ApplicationRequirement;

/// Catalog contract carried into the generated static composition graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedModuleContract {
    /// Stable module ID.
    pub module: &'static str,
    /// Whether configuration may disable this compiled module.
    pub runtime_toggle: bool,
    /// Declared route IDs.
    pub routes: &'static [&'static str],
    /// Declared background-task IDs.
    pub tasks: &'static [&'static str],
    /// Declared health-check IDs.
    pub health_checks: &'static [&'static str],
    /// Application-owned contributions required by this module.
    pub application_requirements: &'static [ApplicationRequirement],
}

/// Immutable inputs generated from the resolved profile selection.
#[derive(Clone, Copy, Debug)]
pub struct CompositionInput {
    /// Selected profile ID.
    pub profile: &'static str,
    /// Selected module IDs in prerequisite-first order.
    pub modules: &'static [&'static str],
    /// Selected provider slots and modules.
    pub providers: &'static [ProviderMetadata],
    /// Selected module contracts in prerequisite-first order.
    pub contracts: &'static [SelectedModuleContract],
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
            contracts: selected::CONTRACTS,
            runtime_disabled_modules,
        }
    }
}
/// Returns whether any selected module requires an application-owned contribution.
#[must_use]
pub fn selected_requires_application_contributions() -> bool {
    selected::CONTRACTS
        .iter()
        .any(|contract| !contract.application_requirements.is_empty())
}


/// Configuration for the generated `/example` local rate limit.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleRateLimitConfig {
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
    /// Secret cursor-signing material.
    #[cfg(feature = "idempotency")]
    pub pagination: PaginationConfig,
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

/// Secret-bearing cursor configuration retained as a secret through construction.
#[cfg(feature = "idempotency")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationConfig {
    /// Cursor authentication key, exactly 32 bytes after environment decoding.
    #[serde(deserialize_with = "deserialize_cursor_signing_key")]
    pub cursor_signing_key: omnius_config::SecretString,
}

#[cfg(feature = "idempotency")]
fn deserialize_cursor_signing_key<'de, D>(
    deserializer: D,
) -> Result<omnius_config::SecretString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use omnius_config::ExposeSecret as _;

    let key = omnius_config::SecretString::deserialize(deserializer)?;
    if key.expose_secret().as_bytes().len() != 32 {
        return Err(serde::de::Error::custom(
            "cursor signing key must be exactly 32 bytes",
        ));
    }
    Ok(key)
}

/// Connected provider resources for the selected persisted reference API.
#[cfg(feature = "idempotency")]
pub struct ApiRuntime {
    pub(crate) pool: omnius_postgres::PostgresPool,
    idempotency: omnius_idempotency::IdempotencyConfig,
    pub(crate) cursor_codec: omnius_pagination::CursorCodec,
    #[cfg(feature = "openapi")]
    openapi: omnius_openapi::OpenApiConfig,
}

#[cfg(feature = "idempotency")]
impl ApiRuntime {
    fn new(
        config: &SelectedRuntimeConfig,
        pool: omnius_postgres::PostgresPool,
    ) -> Result<Self, CompositionError> {
        use omnius_config::ExposeSecret as _;

        let cursor_key = omnius_pagination::CursorSigningKey::from_slice(
            config
                .pagination
                .cursor_signing_key
                .expose_secret()
                .as_bytes(),
        )
        .map_err(|error| CompositionError::construction("idempotency", error))?;
        Ok(Self {
            pool,
            idempotency: config.idempotency,
            cursor_codec: omnius_pagination::CursorCodec::new(cursor_key),
            #[cfg(feature = "openapi")]
            openapi: config.openapi,
        })
    }

    pub(crate) fn idempotency_store(
        &self,
    ) -> Result<omnius_idempotency::PostgresIdempotencyStore, CompositionError> {
        omnius_idempotency::PostgresIdempotencyStore::new(self.idempotency)
            .map_err(|error| CompositionError::construction("idempotency", error))
    }
}

#[cfg(feature = "postgres")]
async fn connect_postgres(
    config: &SelectedRuntimeConfig,
    deployment: omnius_config::DeploymentEnvironment,
    apply_startup_policy: bool,
) -> Result<omnius_postgres::PostgresPool, CompositionError> {
    let pool = omnius_postgres::PostgresPool::connect(&config.postgres, deployment)
        .await
        .map_err(|error| CompositionError::construction("postgres", error))?;
    #[cfg(feature = "migrations")]
    {
        let range = omnius_migrations::SchemaVersionRange::try_from(SchemaCompatibility {
            minimum: "2026082301",
            maximum: "2026082809",
        })
        .map_err(|error| CompositionError::construction("migrations", error))?;
        let runner = omnius_migrations::MigrationRunner::new(
            pool.clone(),
            &omnius_migrations::MIGRATOR,
            range,
            config.migrations,
            deployment,
        )
        .map_err(|error| CompositionError::construction("migrations", error))?;
        if apply_startup_policy {
            runner
                .apply_startup_policy()
                .await
                .map_err(|error| CompositionError::construction("migrations", error))?;
        }
    }
    #[cfg(not(feature = "migrations"))]
    let _ = apply_startup_policy;
    Ok(pool)
}


/// Connected resources selected by compile-time module features.
#[derive(Default)]
pub struct SelectedRuntime {
    #[cfg(feature = "postgres")]
    postgres: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    api: Option<ApiRuntime>,
    #[cfg(feature = "outbound-http")]
    outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
}

impl SelectedRuntime {
    /// Constructs only the provider resources selected by Cargo features.
    pub async fn connect(
        config: &SelectedRuntimeConfig,
        deployment: omnius_config::DeploymentEnvironment,
        apply_startup_policy: bool,
    ) -> Result<Self, CompositionError> {
        #[allow(unused_mut)]
        let mut runtime = Self::default();
        #[cfg(feature = "postgres")]
        {
            let pool = connect_postgres(config, deployment, apply_startup_policy).await?;
            #[cfg(feature = "idempotency")]
            {
                runtime.api = Some(ApiRuntime::new(config, pool.clone())?);
            }
            runtime.postgres = Some(pool);
        }
        #[cfg(feature = "outbound-http")]
        {
            let clients = omnius_outbound_http::OutboundHttpClients::new(&config.outbound_http)
                .map_err(|error| CompositionError::construction("outbound-http", error))?;
            runtime.outbound_http = Some(std::sync::Arc::new(clients));
        }
        #[cfg(not(feature = "postgres"))]
        let _ = (deployment, apply_startup_policy);
        #[cfg(not(any(feature = "postgres", feature = "outbound-http")))]
        let _ = config;
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
pub async fn execute_selected_migration(
    config: &SelectedRuntimeConfig,
    deployment: omnius_config::DeploymentEnvironment,
    profile: &'static str,
    command: SelectedMigrationCommand,
) -> Result<MigrationStatusDocument, CompositionError> {
    #[cfg(feature = "migrations")]
    {
        let pool = omnius_postgres::PostgresPool::connect(&config.postgres, deployment)
            .await
            .map_err(|error| CompositionError::construction("postgres", error))?;
        let operation = async {
            let range = omnius_migrations::SchemaVersionRange::try_from(SchemaCompatibility {
                minimum: "2026082301",
                maximum: "2026082809",
            })
            .map_err(|error| CompositionError::construction("migrations", error))?;
            let runner = omnius_migrations::MigrationRunner::new(
                pool.clone(),
                &omnius_migrations::MIGRATOR,
                range,
                config.migrations,
                deployment,
            )
            .map_err(|error| CompositionError::construction("migrations", error))?;
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
        return match (operation, close) {
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(status), Ok(())) => Ok(status),
        };
    }
    #[cfg(not(feature = "migrations"))]
    {
        let _ = (config, deployment);
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

/// Executes WebAuthn registration and authentication ceremonies.
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
pub struct AdminRuntime {
    authority_resolver: Option<Arc<dyn AdminAuthorityResolverPort>>,
    operation_handler: Option<Arc<dyn AdminOperationHandlerPort>>,
}
impl AdminRuntime {
    port_setter!(with_authority_resolver, authority_resolver, dyn AdminAuthorityResolverPort);
    port_setter!(with_operation_handler, operation_handler, dyn AdminOperationHandlerPort);
}

/// Complete application-owned authentication contract.
#[derive(Default)]
pub struct AuthRuntime {
    authenticated_runtime: Option<Arc<dyn AuthenticatedRuntimePort>>,
    redis_session_runtime: Option<Arc<dyn RedisSessionRuntimePort>>,
    oidc_runtime: Option<Arc<dyn OidcRuntimePort>>,
    oauth_runtime: Option<Arc<dyn OauthRuntimePort>>,
    webauthn_runtime: Option<Arc<dyn WebauthnRuntimePort>>,
    totp_runtime: Option<Arc<dyn TotpRuntimePort>>,
}
impl AuthRuntime {
    port_setter!(with_authenticated_runtime, authenticated_runtime, dyn AuthenticatedRuntimePort);
    port_setter!(with_redis_session_runtime, redis_session_runtime, dyn RedisSessionRuntimePort);
    port_setter!(with_oidc_runtime, oidc_runtime, dyn OidcRuntimePort);
    port_setter!(with_oauth_runtime, oauth_runtime, dyn OauthRuntimePort);
    port_setter!(with_webauthn_runtime, webauthn_runtime, dyn WebauthnRuntimePort);
    port_setter!(with_totp_runtime, totp_runtime, dyn TotpRuntimePort);
}

/// Application-owned billing contract.
#[derive(Default)]
pub struct BillingRuntime {
    provider: Option<Arc<dyn BillingProviderPort>>,
}
impl BillingRuntime {
    port_setter!(with_provider, provider, dyn BillingProviderPort);
}

/// Application-owned feature-flag contract.
#[derive(Default)]
pub struct FeatureFlagsRuntime {
    provider: Option<Arc<dyn FeatureFlagProviderPort>>,
    exposure_recorder: Option<Arc<dyn FeatureFlagExposureRecorderPort>>,
}
impl FeatureFlagsRuntime {
    port_setter!(with_provider, provider, dyn FeatureFlagProviderPort);
    port_setter!(with_exposure_recorder, exposure_recorder, dyn FeatureFlagExposureRecorderPort);
}

/// Application-owned GraphQL contract.
#[derive(Default)]
pub struct GraphqlRuntime {
    schema: Option<Arc<dyn GraphqlSchemaPort>>,
    request_data_injector: Option<Arc<dyn GraphqlRequestDataInjectorPort>>,
}
impl GraphqlRuntime {
    port_setter!(with_schema, schema, dyn GraphqlSchemaPort);
    port_setter!(with_request_data_injector, request_data_injector, dyn GraphqlRequestDataInjectorPort);
}

/// Application-owned gRPC contract.
#[derive(Default)]
pub struct GrpcRuntime {
    application_service: Option<Arc<dyn GrpcApplicationServicePort>>,
    authenticator: Option<Arc<dyn GrpcAuthenticatorPort>>,
    method_policies: Option<Arc<dyn GrpcMethodPoliciesPort>>,
}
impl GrpcRuntime {
    port_setter!(with_application_service, application_service, dyn GrpcApplicationServicePort);
    port_setter!(with_authenticator, authenticator, dyn GrpcAuthenticatorPort);
    port_setter!(with_method_policies, method_policies, dyn GrpcMethodPoliciesPort);
}

/// Application-owned jobs contract.
#[derive(Default)]
pub struct JobsRuntime {
    handlers: Option<Arc<dyn JobsHandlersPort>>,
}
impl JobsRuntime {
    port_setter!(with_handlers, handlers, dyn JobsHandlersPort);
}

/// Application-owned durable inbox contract.
#[derive(Default)]
pub struct InboxRuntime {
    consumers: Option<Arc<dyn InboxConsumersPort>>,
}
impl InboxRuntime {
    port_setter!(with_consumers, consumers, dyn InboxConsumersPort);
}

/// Application-owned outbox contract.
#[derive(Default)]
pub struct OutboxRuntime {
    publisher: Option<Arc<dyn OutboxPublisherPort>>,
}
impl OutboxRuntime {
    port_setter!(with_publisher, publisher, dyn OutboxPublisherPort);
}

/// Application-owned scheduler contract.
#[derive(Default)]
pub struct SchedulerRuntime {
    envelope_factory: Option<Arc<dyn SchedulerEnvelopeFactoryPort>>,
}
impl SchedulerRuntime {
    port_setter!(with_envelope_factory, envelope_factory, dyn SchedulerEnvelopeFactoryPort);
}

/// Application-owned realtime contract.
#[derive(Default)]
pub struct RealtimeRuntime {
    fanout_authorizer: Option<Arc<dyn RealtimeFanoutAuthorizerPort>>,
    identity_revalidator: Option<Arc<dyn RealtimeIdentityRevalidatorPort>>,
    event_handler: Option<Arc<dyn RealtimeEventHandlerPort>>,
}
impl RealtimeRuntime {
    port_setter!(with_fanout_authorizer, fanout_authorizer, dyn RealtimeFanoutAuthorizerPort);
    port_setter!(with_identity_revalidator, identity_revalidator, dyn RealtimeIdentityRevalidatorPort);
    port_setter!(with_event_handler, event_handler, dyn RealtimeEventHandlerPort);
}

/// Application-owned upload contract.
#[derive(Default)]
pub struct UploadsRuntime {
    workflow: Option<Arc<dyn UploadWorkflowPort>>,
    authorization: Option<Arc<dyn UploadAuthorizationPort>>,
}
impl UploadsRuntime {
    port_setter!(with_workflow, workflow, dyn UploadWorkflowPort);
    port_setter!(with_authorization, authorization, dyn UploadAuthorizationPort);
}

/// Application-owned inbound-webhook contract.
#[derive(Default)]
pub struct WebhooksInboundRuntime {
    provider_adapters: Option<Arc<dyn WebhooksInboundProviderAdaptersPort>>,
    handlers: Option<Arc<dyn WebhooksInboundHandlersPort>>,
}
impl WebhooksInboundRuntime {
    port_setter!(with_provider_adapters, provider_adapters, dyn WebhooksInboundProviderAdaptersPort);
    port_setter!(with_handlers, handlers, dyn WebhooksInboundHandlersPort);
}

/// Application-owned Svix webhook contract.
#[derive(Default)]
pub struct WebhooksSvixRuntime {
    replay_admission: Option<Arc<dyn WebhooksSvixReplayAdmissionPort>>,
}
impl WebhooksSvixRuntime {
    port_setter!(with_replay_admission, replay_admission, dyn WebhooksSvixReplayAdmissionPort);
}

/// Application-owned search contract.
#[derive(Default)]
pub struct SearchRuntime {
    index_schema: Option<Arc<dyn SearchIndexSchemaPort>>,
    reauthorizer: Option<Arc<dyn SearchReauthorizerPort>>,
    projection_resolver: Option<Arc<dyn SearchProjectionResolverPort>>,
}
impl SearchRuntime {
    port_setter!(with_index_schema, index_schema, dyn SearchIndexSchemaPort);
    port_setter!(with_reauthorizer, reauthorizer, dyn SearchReauthorizerPort);
    port_setter!(with_projection_resolver, projection_resolver, dyn SearchProjectionResolverPort);
}

/// Application-owned privacy contract.
#[derive(Default)]
pub struct PrivacyRuntime {
    inventory_manifest: Option<Arc<dyn PrivacyInventoryManifestPort>>,
    inventory_adapters: Option<Arc<dyn PrivacyInventoryAdaptersPort>>,
    authorizer: Option<Arc<dyn PrivacyAuthorizerPort>>,
    lifecycle_handler: Option<Arc<dyn PrivacyLifecycleHandlerPort>>,
    consent_policy: Option<Arc<dyn PrivacyConsentPolicyPort>>,
    moderation_policy: Option<Arc<dyn PrivacyModerationPolicyPort>>,
}
impl PrivacyRuntime {
    port_setter!(with_inventory_manifest, inventory_manifest, dyn PrivacyInventoryManifestPort);
    port_setter!(with_inventory_adapters, inventory_adapters, dyn PrivacyInventoryAdaptersPort);
    port_setter!(with_authorizer, authorizer, dyn PrivacyAuthorizerPort);
    port_setter!(with_lifecycle_handler, lifecycle_handler, dyn PrivacyLifecycleHandlerPort);
    port_setter!(with_consent_policy, consent_policy, dyn PrivacyConsentPolicyPort);
    port_setter!(with_moderation_policy, moderation_policy, dyn PrivacyModerationPolicyPort);
}

/// Application-owned LLM contract.
#[derive(Default)]
pub struct LlmRuntime {
    tool_authorization: Option<Arc<dyn LlmToolAuthorizationPort>>,
    tool_audit: Option<Arc<dyn LlmToolAuditPort>>,
    media_scanner: Option<Arc<dyn LlmMediaScannerPort>>,
    media_authorization: Option<Arc<dyn LlmMediaAuthorizationPort>>,
    evaluation_repository: Option<Arc<dyn LlmEvaluationRepositoryPort>>,
}
impl LlmRuntime {
    port_setter!(with_tool_authorization, tool_authorization, dyn LlmToolAuthorizationPort);
    port_setter!(with_tool_audit, tool_audit, dyn LlmToolAuditPort);
    port_setter!(with_media_scanner, media_scanner, dyn LlmMediaScannerPort);
    port_setter!(with_media_authorization, media_authorization, dyn LlmMediaAuthorizationPort);
    port_setter!(with_evaluation_repository, evaluation_repository, dyn LlmEvaluationRepositoryPort);
}

/// Application-owned MCP core contract.
#[derive(Default)]
pub struct McpCoreRuntime {
    capability_registry: Option<Arc<dyn McpCapabilityRegistryPort>>,
}
impl McpCoreRuntime {
    port_setter!(with_capability_registry, capability_registry, dyn McpCapabilityRegistryPort);
}

/// Application-owned MCP authentication contract.
#[derive(Default)]
pub struct McpAuthRuntime {
    bearer_authenticator: Option<Arc<dyn McpBearerAuthenticatorPort>>,
}
impl McpAuthRuntime {
    port_setter!(with_bearer_authenticator, bearer_authenticator, dyn McpBearerAuthenticatorPort);
}

/// Application-owned MCP enterprise contract.
#[derive(Default)]
pub struct McpEnterpriseRuntime {
    ports: Option<Arc<dyn McpEnterprisePorts>>,
}
impl McpEnterpriseRuntime {
    port_setter!(with_ports, ports, dyn McpEnterprisePorts);
}

/// Application-owned MCP subscription contract.
#[derive(Default)]
pub struct McpSubscriptionsRuntime {
    repository: Option<Arc<dyn McpSubscriptionRepositoryPort>>,
    authorizer: Option<Arc<dyn McpSubscriptionAuthorizerPort>>,
    runtime: Option<Arc<dyn McpSubscriptionRuntimePort>>,
    delivery: Option<Arc<dyn McpSubscriptionDeliveryPort>>,
}
impl McpSubscriptionsRuntime {
    port_setter!(with_repository, repository, dyn McpSubscriptionRepositoryPort);
    port_setter!(with_authorizer, authorizer, dyn McpSubscriptionAuthorizerPort);
    port_setter!(with_runtime, runtime, dyn McpSubscriptionRuntimePort);
    port_setter!(with_delivery, delivery, dyn McpSubscriptionDeliveryPort);
}

/// Application-owned durable MCP task contract.
#[derive(Default)]
pub struct McpTasksRuntime {
    payload_protector: Option<Arc<dyn McpTaskPayloadProtectorPort>>,
    cancellation_runtime: Option<Arc<dyn McpCancellationRuntimePort>>,
    capability_executor: Option<Arc<dyn McpCapabilityExecutorPort>>,
}
impl McpTasksRuntime {
    port_setter!(with_payload_protector, payload_protector, dyn McpTaskPayloadProtectorPort);
    port_setter!(with_cancellation_runtime, cancellation_runtime, dyn McpCancellationRuntimePort);
    port_setter!(with_capability_executor, capability_executor, dyn McpCapabilityExecutorPort);
}

/// Application-owned MCP Apps contract.
#[derive(Default)]
pub struct McpAppsRuntime {
    ports: Option<Arc<dyn McpAppsPorts>>,
}
impl McpAppsRuntime {
    port_setter!(with_ports, ports, dyn McpAppsPorts);
}

/// Mounted contract metadata runtime supplied by the generated root.
pub struct ConsumerContractsRuntime {
    router: Router,
    openapi_fragment: Option<serde_json::Value>,
}
impl ConsumerContractsRuntime {
    /// Creates the mounted metadata runtime.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self { router, openapi_fragment: None }
    }
    /// Attaches the contract fragment emitted by the mounted runtime.
    #[must_use]
    pub fn with_openapi_fragment(mut self, fragment: serde_json::Value) -> Self {
        self.openapi_fragment = Some(fragment);
        self
    }
}

/// Validated static-delivery runtime.
pub struct WebStaticRuntime {
    router: Router,
}
impl WebStaticRuntime {
    /// Creates a runtime from the validated delivery router.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self { router }
    }
}

/// Connected Redis/Apalis worker outputs.
pub struct JobsApalisRedisRuntime {
    readiness: HealthCheckSpec,
    worker: TaskSpec,
}
impl JobsApalisRedisRuntime {
    /// Creates provider outputs after a typed handler is bound.
    #[must_use]
    pub fn new(readiness: HealthCheckSpec, worker: TaskSpec) -> Self {
        Self { readiness, worker }
    }
}

/// Verified PGMQ worker outputs.
pub struct JobsPgmqRuntime {
    readiness: HealthCheckSpec,
    worker: TaskSpec,
}
impl JobsPgmqRuntime {
    /// Creates provider outputs after a typed handler is bound.
    #[must_use]
    pub fn new(readiness: HealthCheckSpec, worker: TaskSpec) -> Self {
        Self { readiness, worker }
    }
}

/// Runtime output for one optional router.
pub struct RouterRuntime {
    router: Router,
}
impl RouterRuntime {
    /// Creates a named module router output.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self { router }
    }
}

/// Runtime output for one supervised task.
pub struct TaskRuntime {
    task: TaskSpec,
}
impl TaskRuntime {
    /// Creates a named module task output.
    #[must_use]
    pub fn new(task: TaskSpec) -> Self {
        Self { task }
    }
}

/// Runtime output for one health check.
pub struct HealthRuntime {
    health: HealthCheckSpec,
}
impl HealthRuntime {
    /// Creates a named module health output.
    #[must_use]
    pub fn new(health: HealthCheckSpec) -> Self {
        Self { health }
    }
}

/// Runtime outputs for a task-backed provider with readiness.
pub struct TaskHealthRuntime {
    task: TaskSpec,
    health: HealthCheckSpec,
}
impl TaskHealthRuntime {
    /// Creates task and health outputs.
    #[must_use]
    pub fn new(task: TaskSpec, health: HealthCheckSpec) -> Self {
        Self { task, health }
    }
}

/// Runtime outputs for a routed background processor.
pub struct RouterTaskRuntime {
    router: Router,
    task: TaskSpec,
}
impl RouterTaskRuntime {
    /// Creates router and task outputs.
    #[must_use]
    pub fn new(router: Router, task: TaskSpec) -> Self {
        Self { router, task }
    }
}

/// Runtime outputs for an authenticated router with readiness.
pub struct RouterHealthRuntime {
    router: Router,
    health: HealthCheckSpec,
}
impl RouterHealthRuntime {
    /// Creates router and health outputs.
    #[must_use]
    pub fn new(router: Router, health: HealthCheckSpec) -> Self {
        Self { router, health }
    }
}

macro_rules! runtime_setter {
    ($method:ident, $field:ident, $type:ty) => {
        #[doc = concat!("Supplies the named `", stringify!($field), "` runtime.")]
        #[must_use]
        pub fn $method(mut self, runtime: $type) -> Self {
            self.$field = Some(runtime);
            self
        }
    };
}

/// Application-owned typed domain ports and their validated runtime outputs.
///
/// Port families are separate from module outputs: a router, task, health
/// check, or OpenAPI fragment never proves that an application policy exists.
#[derive(Default)]
pub struct ApplicationContributions {
    example_router: Option<Router>,
    example_rate_limit: Option<ExampleRateLimitConfig>,
    #[cfg(feature = "postgres")]
    postgres_pool: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "outbound-http")]
    outbound_http: Option<Arc<omnius_outbound_http::OutboundHttpClients>>,
    #[cfg(feature = "idempotency")]
    api_runtime: Option<ApiRuntime>,
    admin: Option<AdminRuntime>,
    auth: Option<AuthRuntime>,
    billing: Option<BillingRuntime>,
    feature_flags: Option<FeatureFlagsRuntime>,
    graphql: Option<GraphqlRuntime>,
    grpc: Option<GrpcRuntime>,
    inbox: Option<InboxRuntime>,
    jobs: Option<JobsRuntime>,
    llm: Option<LlmRuntime>,
    mcp_apps: Option<McpAppsRuntime>,
    mcp_auth: Option<McpAuthRuntime>,
    mcp_core: Option<McpCoreRuntime>,
    mcp_enterprise: Option<McpEnterpriseRuntime>,
    mcp_subscriptions: Option<McpSubscriptionsRuntime>,
    mcp_tasks: Option<McpTasksRuntime>,
    outbox: Option<OutboxRuntime>,
    privacy: Option<PrivacyRuntime>,
    realtime: Option<RealtimeRuntime>,
    scheduler: Option<SchedulerRuntime>,
    search: Option<SearchRuntime>,
    uploads: Option<UploadsRuntime>,
    webhooks_inbound: Option<WebhooksInboundRuntime>,
    webhooks_svix: Option<WebhooksSvixRuntime>,
    consumer_contracts_output: Option<ConsumerContractsRuntime>,
    web_static_output: Option<WebStaticRuntime>,
    jobs_apalis_redis_output: Option<JobsApalisRedisRuntime>,
    jobs_pgmq_output: Option<JobsPgmqRuntime>,
    outbox_output: Option<TaskRuntime>,
    scheduler_output: Option<TaskRuntime>,
    events_nats_output: Option<TaskHealthRuntime>,
    events_redis_output: Option<TaskRuntime>,
    sse_output: Option<RouterRuntime>,
    websockets_output: Option<RouterRuntime>,
    object_storage_output: Option<HealthRuntime>,
    email_output: Option<HealthRuntime>,
    notifications_output: Option<TaskRuntime>,
    webhooks_svix_output: Option<HealthRuntime>,
    webhooks_inbound_output: Option<RouterTaskRuntime>,
    auth_oidc_output: Option<RouterTaskRuntime>,
    auth_webauthn_output: Option<RouterRuntime>,
    auth_totp_output: Option<RouterRuntime>,
    mcp_http_output: Option<RouterHealthRuntime>,
    mcp_auth_oauth_output: Option<RouterRuntime>,
    mcp_subscriptions_local_output: Option<TaskRuntime>,
    mcp_subscriptions_redis_output: Option<TaskRuntime>,
    mcp_subscriptions_nats_output: Option<TaskRuntime>,
    mcp_tasks_output: Option<TaskRuntime>,
    llm_provider_rig_output: Option<HealthRuntime>,
    llm_provider_bedrock_output: Option<HealthRuntime>,
    llm_provider_vertex_output: Option<HealthRuntime>,
    llm_routing_output: Option<HealthRuntime>,
    llm_tool_runtime_output: Option<TaskRuntime>,
    llm_media_output: Option<TaskRuntime>,
    llm_http_api_output: Option<RouterRuntime>,
}

impl ApplicationContributions {
    /// Creates an empty, fail-closed contribution set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies the concrete resources owned by the generated base application.
    #[must_use]
    pub fn with_base(
        mut self,
        example_router: Router,
        example_rate_limit: ExampleRateLimitConfig,
    ) -> Self {
        self.example_router = Some(example_router);
        self.example_rate_limit = Some(example_rate_limit);
        self
    }

    /// Supplies resources constructed from feature-gated selected configuration.
    #[must_use]
    pub fn with_selected_runtime(mut self, runtime: SelectedRuntime) -> Self {
        #[cfg(feature = "postgres")]
        {
            self.postgres_pool = runtime.postgres;
        }
        #[cfg(feature = "idempotency")]
        {
            self.api_runtime = runtime.api;
        }
        #[cfg(feature = "outbound-http")]
        {
            self.outbound_http = runtime.outbound_http;
        }
        #[cfg(not(any(
            feature = "postgres",
            feature = "idempotency",
            feature = "outbound-http"
        )))]
        let _ = runtime;
        self
    }

    runtime_setter!(with_admin_runtime, admin, AdminRuntime);
    runtime_setter!(with_auth_runtime, auth, AuthRuntime);
    runtime_setter!(with_billing_runtime, billing, BillingRuntime);
    runtime_setter!(with_feature_flags_runtime, feature_flags, FeatureFlagsRuntime);
    runtime_setter!(with_graphql_runtime, graphql, GraphqlRuntime);
    runtime_setter!(with_grpc_runtime, grpc, GrpcRuntime);
    runtime_setter!(with_inbox_runtime, inbox, InboxRuntime);
    runtime_setter!(with_jobs_runtime, jobs, JobsRuntime);
    runtime_setter!(with_llm_runtime, llm, LlmRuntime);
    runtime_setter!(with_mcp_apps_runtime, mcp_apps, McpAppsRuntime);
    runtime_setter!(with_mcp_auth_runtime, mcp_auth, McpAuthRuntime);
    runtime_setter!(with_mcp_core_runtime, mcp_core, McpCoreRuntime);
    runtime_setter!(with_mcp_enterprise_runtime, mcp_enterprise, McpEnterpriseRuntime);
    runtime_setter!(
        with_mcp_subscriptions_runtime,
        mcp_subscriptions,
        McpSubscriptionsRuntime
    );
    runtime_setter!(with_mcp_tasks_runtime, mcp_tasks, McpTasksRuntime);
    runtime_setter!(with_outbox_runtime, outbox, OutboxRuntime);
    runtime_setter!(with_privacy_runtime, privacy, PrivacyRuntime);
    runtime_setter!(with_realtime_runtime, realtime, RealtimeRuntime);
    runtime_setter!(with_scheduler_runtime, scheduler, SchedulerRuntime);
    runtime_setter!(with_search_runtime, search, SearchRuntime);
    runtime_setter!(with_uploads_runtime, uploads, UploadsRuntime);
    runtime_setter!(
        with_webhooks_inbound_runtime,
        webhooks_inbound,
        WebhooksInboundRuntime
    );
    runtime_setter!(with_webhooks_svix_runtime, webhooks_svix, WebhooksSvixRuntime);

    runtime_setter!(
        with_consumer_contracts,
        consumer_contracts_output,
        ConsumerContractsRuntime
    );
    runtime_setter!(with_web_static, web_static_output, WebStaticRuntime);
    runtime_setter!(
        with_jobs_apalis_redis,
        jobs_apalis_redis_output,
        JobsApalisRedisRuntime
    );
    runtime_setter!(with_jobs_pgmq, jobs_pgmq_output, JobsPgmqRuntime);
    runtime_setter!(with_outbox_output, outbox_output, TaskRuntime);
    runtime_setter!(with_scheduler_output, scheduler_output, TaskRuntime);
    runtime_setter!(with_events_nats_output, events_nats_output, TaskHealthRuntime);
    runtime_setter!(with_events_redis_output, events_redis_output, TaskRuntime);
    runtime_setter!(with_sse_output, sse_output, RouterRuntime);
    runtime_setter!(with_websockets_output, websockets_output, RouterRuntime);
    runtime_setter!(with_object_storage_output, object_storage_output, HealthRuntime);
    runtime_setter!(with_email_output, email_output, HealthRuntime);
    runtime_setter!(with_notifications_output, notifications_output, TaskRuntime);
    runtime_setter!(with_webhooks_svix_output, webhooks_svix_output, HealthRuntime);
    runtime_setter!(
        with_webhooks_inbound_output,
        webhooks_inbound_output,
        RouterTaskRuntime
    );
    runtime_setter!(with_auth_oidc_output, auth_oidc_output, RouterTaskRuntime);
    runtime_setter!(with_auth_webauthn_output, auth_webauthn_output, RouterRuntime);
    runtime_setter!(with_auth_totp_output, auth_totp_output, RouterRuntime);
    runtime_setter!(with_mcp_http_output, mcp_http_output, RouterHealthRuntime);
    runtime_setter!(with_mcp_auth_oauth_output, mcp_auth_oauth_output, RouterRuntime);
    runtime_setter!(
        with_mcp_subscriptions_local_output,
        mcp_subscriptions_local_output,
        TaskRuntime
    );
    runtime_setter!(
        with_mcp_subscriptions_redis_output,
        mcp_subscriptions_redis_output,
        TaskRuntime
    );
    runtime_setter!(
        with_mcp_subscriptions_nats_output,
        mcp_subscriptions_nats_output,
        TaskRuntime
    );
    runtime_setter!(with_mcp_tasks_output, mcp_tasks_output, TaskRuntime);
    runtime_setter!(with_llm_provider_rig_output, llm_provider_rig_output, HealthRuntime);
    runtime_setter!(
        with_llm_provider_bedrock_output,
        llm_provider_bedrock_output,
        HealthRuntime
    );
    runtime_setter!(
        with_llm_provider_vertex_output,
        llm_provider_vertex_output,
        HealthRuntime
    );
    runtime_setter!(with_llm_routing_output, llm_routing_output, HealthRuntime);
    runtime_setter!(with_llm_tool_runtime_output, llm_tool_runtime_output, TaskRuntime);
    runtime_setter!(with_llm_media_output, llm_media_output, TaskRuntime);
    runtime_setter!(with_llm_http_api_output, llm_http_api_output, RouterRuntime);
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

/// Selection-driven application builder populated by static registrars.
pub struct AppCompositionBuilder<'a> {
    input: CompositionInput,
    contributions: &'a mut ApplicationContributions,
    routers: Vec<Router>,
    health_specs: Vec<HealthCheckSpec>,
    health_runtime: bool,
    task_specs: Vec<TaskSpec>,
    route_ids: BTreeSet<&'static str>,
    health_ids: BTreeSet<&'static str>,
    task_ids: BTreeSet<&'static str>,
    public_operations: BTreeSet<&'static str>,
    capabilities: BTreeMap<&'static str, bool>,
    openapi_fragments: Vec<serde_json::Value>,
}

impl<'a> AppCompositionBuilder<'a> {
    /// Creates a builder for one resolved profile and application boundary.
    #[must_use]
    pub fn new(input: CompositionInput, contributions: &'a mut ApplicationContributions) -> Self {
        Self {
            input,
            contributions,
            routers: Vec::new(),
            health_runtime: false,
            health_specs: Vec::new(),
            task_specs: Vec::new(),
            route_ids: BTreeSet::new(),
            health_ids: BTreeSet::new(),
            task_ids: BTreeSet::new(),
            public_operations: BTreeSet::new(),
            capabilities: BTreeMap::new(),
            openapi_fragments: Vec::new(),
        }
    }

    /// Executes the generated prerequisite-first registrar list.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when a registrar cannot construct its
    /// selected contribution.
    pub async fn register_selected(&mut self) -> Result<(), CompositionError> {
        selected::register_selected(self).await
    }

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

    pub(crate) fn runtime_available(&self, module: &str) -> bool {
        !self.input.runtime_disabled_modules.contains(&module)
    }


    pub(crate) fn example_router(&self, module: &'static str) -> Result<Router, CompositionError> {
        self.contributions
            .example_router
            .clone()
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "base.example-router",
            })
    }

    pub(crate) fn example_rate_limit(
        &self,
        module: &'static str,
    ) -> Result<ExampleRateLimitConfig, CompositionError> {
        self.contributions
            .example_rate_limit
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "base.example-rate-limit",
            })
    }

    pub(crate) fn module_selected(&self, module: &str) -> bool {
        self.input.modules.contains(&module)
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
    pub(crate) fn api_runtime(
        &self,
        module: &'static str,
    ) -> Result<&ApiRuntime, CompositionError> {
        self.contributions
            .api_runtime
            .as_ref()
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "reference-api.runtime",
            })
    }
    /// Validates one generated application requirement against its exact typed field.
    pub fn require(
        &self,
        module: &'static str,
        requirement: ApplicationRequirement,
    ) -> Result<(), CompositionError> {
        let present = match requirement {
            ApplicationRequirement::AdminAuthorityResolver => self
                .contributions
                .admin
                .as_ref()
                .map(|runtime| runtime.authority_resolver.is_some()),
            ApplicationRequirement::AdminOperationHandler => self
                .contributions
                .admin
                .as_ref()
                .map(|runtime| runtime.operation_handler.is_some()),
            ApplicationRequirement::AuthAuthenticatedRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.authenticated_runtime.is_some()),
            ApplicationRequirement::AuthRedisSessionRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.redis_session_runtime.is_some()),
            ApplicationRequirement::AuthOidcRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.oidc_runtime.is_some()),
            ApplicationRequirement::AuthOauthRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.oauth_runtime.is_some()),
            ApplicationRequirement::AuthWebAuthnRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.webauthn_runtime.is_some()),
            ApplicationRequirement::AuthTotpRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.totp_runtime.is_some()),
            ApplicationRequirement::BillingProvider => self
                .contributions
                .billing
                .as_ref()
                .map(|runtime| runtime.provider.is_some()),
            ApplicationRequirement::FeatureFlagsExposureRecorder => self
                .contributions
                .feature_flags
                .as_ref()
                .map(|runtime| runtime.exposure_recorder.is_some()),
            ApplicationRequirement::FeatureFlagsProvider => self
                .contributions
                .feature_flags
                .as_ref()
                .map(|runtime| runtime.provider.is_some()),
            ApplicationRequirement::GraphqlRequestDataInjector => self
                .contributions
                .graphql
                .as_ref()
                .map(|runtime| runtime.request_data_injector.is_some()),
            ApplicationRequirement::GraphqlSchema => self
                .contributions
                .graphql
                .as_ref()
                .map(|runtime| runtime.schema.is_some()),
            ApplicationRequirement::GrpcApplicationService => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.application_service.is_some()),
            ApplicationRequirement::GrpcAuthenticator => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.authenticator.is_some()),
            ApplicationRequirement::GrpcMethodPolicies => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.method_policies.is_some()),
            ApplicationRequirement::InboxConsumers => self
                .contributions
                .inbox
                .as_ref()
                .map(|runtime| runtime.consumers.is_some()),
            ApplicationRequirement::JobsHandlers => self
                .contributions
                .jobs
                .as_ref()
                .map(|runtime| runtime.handlers.is_some()),
            ApplicationRequirement::LlmEvaluationRepository => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.evaluation_repository.is_some()),
            ApplicationRequirement::LlmMediaAuthorization => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.media_authorization.is_some()),
            ApplicationRequirement::LlmMediaScanner => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.media_scanner.is_some()),
            ApplicationRequirement::LlmToolAudit => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.tool_audit.is_some()),
            ApplicationRequirement::LlmToolAuthorization => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.tool_authorization.is_some()),
            ApplicationRequirement::McpAppsPorts => self
                .contributions
                .mcp_apps
                .as_ref()
                .map(|runtime| runtime.ports.is_some()),
            ApplicationRequirement::McpBearerAuthenticator => self
                .contributions
                .mcp_auth
                .as_ref()
                .map(|runtime| runtime.bearer_authenticator.is_some()),
            ApplicationRequirement::McpCancellationRuntime => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.cancellation_runtime.is_some()),
            ApplicationRequirement::McpCapabilityExecutor => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.capability_executor.is_some()),
            ApplicationRequirement::McpCapabilityRegistry => self
                .contributions
                .mcp_core
                .as_ref()
                .map(|runtime| runtime.capability_registry.is_some()),
            ApplicationRequirement::McpEnterprisePorts => self
                .contributions
                .mcp_enterprise
                .as_ref()
                .map(|runtime| runtime.ports.is_some()),
            ApplicationRequirement::McpSubscriptionAuthorizer => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.authorizer.is_some()),
            ApplicationRequirement::McpSubscriptionDelivery => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.delivery.is_some()),
            ApplicationRequirement::McpSubscriptionRepository => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.repository.is_some()),
            ApplicationRequirement::McpSubscriptionRuntime => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.runtime.is_some()),
            ApplicationRequirement::McpTaskPayloadProtector => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.payload_protector.is_some()),
            ApplicationRequirement::OutboxPublisher => self
                .contributions
                .outbox
                .as_ref()
                .map(|runtime| runtime.publisher.is_some()),
            ApplicationRequirement::PrivacyAuthorizer => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.authorizer.is_some()),
            ApplicationRequirement::PrivacyConsentPolicy => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.consent_policy.is_some()),
            ApplicationRequirement::PrivacyInventoryAdapters => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.inventory_adapters.is_some()),
            ApplicationRequirement::PrivacyInventoryManifest => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.inventory_manifest.is_some()),
            ApplicationRequirement::PrivacyLifecycleHandler => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.lifecycle_handler.is_some()),
            ApplicationRequirement::PrivacyModerationPolicy => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.moderation_policy.is_some()),
            ApplicationRequirement::RealtimeEventHandler => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.event_handler.is_some()),
            ApplicationRequirement::RealtimeFanoutAuthorizer => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.fanout_authorizer.is_some()),
            ApplicationRequirement::RealtimeIdentityRevalidator => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.identity_revalidator.is_some()),
            ApplicationRequirement::SchedulerEnvelopeFactory => self
                .contributions
                .scheduler
                .as_ref()
                .map(|runtime| runtime.envelope_factory.is_some()),
            ApplicationRequirement::SearchIndexSchema => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.index_schema.is_some()),
            ApplicationRequirement::SearchProjectionResolver => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.projection_resolver.is_some()),
            ApplicationRequirement::SearchReauthorizer => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.reauthorizer.is_some()),
            ApplicationRequirement::UploadsAuthorization => self
                .contributions
                .uploads
                .as_ref()
                .map(|runtime| runtime.authorization.is_some()),
            ApplicationRequirement::UploadsWorkflow => self
                .contributions
                .uploads
                .as_ref()
                .map(|runtime| runtime.workflow.is_some()),
            ApplicationRequirement::WebhooksInboundHandlers => self
                .contributions
                .webhooks_inbound
                .as_ref()
                .map(|runtime| runtime.handlers.is_some()),
            ApplicationRequirement::WebhooksInboundProviderAdapters => self
                .contributions
                .webhooks_inbound
                .as_ref()
                .map(|runtime| runtime.provider_adapters.is_some()),
            ApplicationRequirement::WebhooksSvixReplayAdmission => self
                .contributions
                .webhooks_svix
                .as_ref()
                .map(|runtime| runtime.replay_admission.is_some()),
        };
        match present {
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

    fn missing_runtime(module: &'static str) -> CompositionError {
        CompositionError::ContractMismatch {
            kind: "runtime",
            id: module,
        }
    }

    pub(crate) fn register_consumer_contracts(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("consumer-contracts")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .consumer_contracts_output
            .take()
            .ok_or_else(|| Self::missing_runtime("consumer-contracts"))?;
        self.register_router(runtime.router, &["GET /api/_meta"])?;
        self.register_public_operation("getRuntimeMetadata")?;
        if let Some(fragment) = runtime.openapi_fragment {
            self.register_openapi(fragment)?;
        }
        Ok(())
    }

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

    pub(crate) fn register_inbox(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("inbox").map(|_| ())
    }

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

    pub(crate) fn register_realtime_core(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("realtime-core").map(|_| ())
    }

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

    pub(crate) fn register_feature_flags(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("feature-flags").map(|_| ())
    }

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

    pub(crate) fn register_mcp_core(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("mcp-server-core").map(|_| ())
    }

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

    pub(crate) fn register_mcp_subscriptions_local(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-local", |c| {
            c.mcp_subscriptions_local_output.take()
        })
    }

    pub(crate) fn register_mcp_subscriptions_redis(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-redis", |c| {
            c.mcp_subscriptions_redis_output.take()
        })
    }

    pub(crate) fn register_mcp_subscriptions_nats(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-nats", |c| {
            c.mcp_subscriptions_nats_output.take()
        })
    }

    fn register_mcp_subscription_output(
        &mut self,
        module: &'static str,
        take: impl FnOnce(&mut ApplicationContributions) -> Option<TaskRuntime>,
    ) -> Result<(), CompositionError> {
        if !self.prepare_module(module)? {
            return Ok(());
        }
        let runtime =
            take(self.contributions).ok_or_else(|| Self::missing_runtime(module))?;
        self.register_task("mcp-subscription-backplane", runtime.task)
    }

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

    pub(crate) fn register_llm_provider_rig(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-rig", "configured-provider-route-availability", |c| {
            c.llm_provider_rig_output.take()
        })
    }

    pub(crate) fn register_llm_provider_bedrock(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-bedrock", "bedrock-route-availability", |c| {
            c.llm_provider_bedrock_output.take()
        })
    }

    pub(crate) fn register_llm_provider_vertex(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-vertex", "vertex-route-availability", |c| {
            c.llm_provider_vertex_output.take()
        })
    }

    pub(crate) fn register_llm_routing(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-routing", "required-route-availability", |c| {
            c.llm_routing_output.take()
        })
    }

    fn register_llm_health_output(
        &mut self,
        module: &'static str,
        health_id: &'static str,
        take: impl FnOnce(&mut ApplicationContributions) -> Option<HealthRuntime>,
    ) -> Result<(), CompositionError> {
        if !self.prepare_module(module)? {
            return Ok(());
        }
        let runtime =
            take(self.contributions).ok_or_else(|| Self::missing_runtime(module))?;
        self.register_health(health_id, runtime.health)
    }

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

    pub(crate) fn register_llm_evals(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("llm-evals").map(|_| ())
    }

    pub(crate) fn register_openapi(
        &mut self,
        fragment: serde_json::Value,
    ) -> Result<(), CompositionError> {
        self.openapi_fragments.push(fragment);
        Ok(())
    }

    /// Mounts a router and records exactly the route IDs it serves.
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

    /// Records an operation only after its serving router has been mounted.
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
    fn install_openapi_catalog(&mut self) -> Result<(), CompositionError> {
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
        let config = self.api_runtime("openapi")?.openapi;
        if !config.document_route_enabled || !config.docs_route_enabled {
            return Err(CompositionError::InvalidConfiguration { module: "openapi" });
        }
        let document = serde_json::from_str(include_str!("../../../contracts/openapi.json"))
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
    pub fn finish(mut self) -> Result<ComposedApplication, CompositionError> {
        #[cfg(feature = "openapi")]
        self.install_openapi_catalog()?;
        for contract in self.input.contracts {
            let enabled = !contract.runtime_toggle
                || !self
                    .input
                    .runtime_disabled_modules
                    .contains(&contract.module);
            if !enabled {
                continue;
            }
            for requirement in contract.application_requirements {
                self.require(contract.module, *requirement)?;
            }
        }
        validate_contract_ids(
            self.input.contracts,
            self.input.runtime_disabled_modules,
            "route",
            |contract| contract.routes,
            &self.route_ids,
        )?;
        validate_contract_ids(
            self.input.contracts,
            self.input.runtime_disabled_modules,
            "task",
            |contract| contract.tasks,
            &self.task_ids,
        )?;
        validate_contract_ids(
            self.input.contracts,
            self.input.runtime_disabled_modules,
            "health",
            |contract| contract.health_checks,
            &self.health_ids,
        )?;
        let router = self.routers.into_iter().fold(Router::new(), Router::merge);
        Ok(ComposedApplication {
            router,
            health_runtime: self.health_runtime,
            health_specs: self.health_specs,
            task_specs: self.task_specs,
            public_operations: self.public_operations,
            capabilities: self.capabilities,
            openapi_fragments: self.openapi_fragments,
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
    openapi_fragments: Vec<serde_json::Value>,
}

impl ComposedApplication {
    /// Consumes the composition into its router, cached health checks, deferred
    /// health-runtime marker, supervised tasks, and contract fragments.
    #[must_use]
    pub fn into_runtime_parts(
        self,
    ) -> (
        Router,
        Vec<HealthCheckSpec>,
        bool,
        Vec<TaskSpec>,
        Vec<serde_json::Value>,
    ) {
        (
            self.router,
            self.health_specs,
            self.health_runtime,
            self.task_specs,
            self.openapi_fragments,
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

    pub(crate) fn construction(module: &'static str, _error: impl Error) -> Self {
        Self::InvalidConfiguration { module }
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

    fn present(requirement: ApplicationRequirement) -> ApplicationContributions {
        let probe = Arc::new(ContractProbe);
        match requirement {
            ApplicationRequirement::AdminAuthorityResolver => ApplicationContributions::new()
                .with_admin_runtime(
                    AdminRuntime::default().with_authority_resolver(probe),
                ),
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
            ApplicationRequirement::BillingProvider => ApplicationContributions::new()
                .with_billing_runtime(BillingRuntime::default().with_provider(probe)),
            ApplicationRequirement::FeatureFlagsExposureRecorder => ApplicationContributions::new()
                .with_feature_flags_runtime(
                    FeatureFlagsRuntime::default().with_exposure_recorder(probe),
                ),
            ApplicationRequirement::FeatureFlagsProvider => ApplicationContributions::new()
                .with_feature_flags_runtime(FeatureFlagsRuntime::default().with_provider(probe)),
            ApplicationRequirement::GraphqlRequestDataInjector => ApplicationContributions::new()
                .with_graphql_runtime(
                    GraphqlRuntime::default().with_request_data_injector(probe),
                ),
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
            ApplicationRequirement::McpAppsPorts => ApplicationContributions::new()
                .with_mcp_apps_runtime(McpAppsRuntime::default().with_ports(probe)),
            ApplicationRequirement::McpBearerAuthenticator => ApplicationContributions::new()
                .with_mcp_auth_runtime(
                    McpAuthRuntime::default().with_bearer_authenticator(probe),
                ),
            ApplicationRequirement::McpCancellationRuntime => ApplicationContributions::new()
                .with_mcp_tasks_runtime(
                    McpTasksRuntime::default().with_cancellation_runtime(probe),
                ),
            ApplicationRequirement::McpCapabilityExecutor => ApplicationContributions::new()
                .with_mcp_tasks_runtime(
                    McpTasksRuntime::default().with_capability_executor(probe),
                ),
            ApplicationRequirement::McpCapabilityRegistry => ApplicationContributions::new()
                .with_mcp_core_runtime(
                    McpCoreRuntime::default().with_capability_registry(probe),
                ),
            ApplicationRequirement::McpEnterprisePorts => ApplicationContributions::new()
                .with_mcp_enterprise_runtime(
                    McpEnterpriseRuntime::default().with_ports(probe),
                ),
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
                .with_mcp_tasks_runtime(
                    McpTasksRuntime::default().with_payload_protector(probe),
                ),
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
            ApplicationRequirement::RealtimeEventHandler => ApplicationContributions::new()
                .with_realtime_runtime(RealtimeRuntime::default().with_event_handler(probe)),
            ApplicationRequirement::RealtimeFanoutAuthorizer => ApplicationContributions::new()
                .with_realtime_runtime(
                    RealtimeRuntime::default().with_fanout_authorizer(probe),
                ),
            ApplicationRequirement::RealtimeIdentityRevalidator => ApplicationContributions::new()
                .with_realtime_runtime(
                    RealtimeRuntime::default().with_identity_revalidator(probe),
                ),
            ApplicationRequirement::SchedulerEnvelopeFactory => ApplicationContributions::new()
                .with_scheduler_runtime(
                    SchedulerRuntime::default().with_envelope_factory(probe),
                ),
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
            ApplicationRequirement::SchedulerEnvelopeFactory => ApplicationContributions::new()
                .with_scheduler_runtime(SchedulerRuntime::default()),
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
}
