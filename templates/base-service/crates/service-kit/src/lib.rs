//! Static application composition for generated services.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
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
    pub application_requirements: &'static [&'static str],
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

/// Secret-bearing cursor configuration retained as a secret through construction.
#[cfg(feature = "idempotency")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationConfig {
    /// Cursor authentication key.
    pub cursor_signing_key: omnius_config::SecretString,
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

struct ModuleRuntimeContribution {
    router: Option<Router>,
    health_specs: Vec<HealthCheckSpec>,
    task_specs: Vec<TaskSpec>,
    openapi_fragments: Vec<serde_json::Value>,
}

macro_rules! runtime_contribution {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        pub struct $name(ModuleRuntimeContribution);

        impl $name {
            /// Creates a contribution from already constructed runtime resources.
            ///
            /// Registrars validate the resource counts against the selected catalog
            /// contract before recording any route, task, or health ID.
            #[must_use]
            pub fn new(
                router: Option<Router>,
                health_specs: Vec<HealthCheckSpec>,
                task_specs: Vec<TaskSpec>,
            ) -> Self {
                Self(ModuleRuntimeContribution {
                    router,
                    health_specs,
                    task_specs,
                    openapi_fragments: Vec::new(),
                })
            }

            /// Adds a contract fragment emitted by the same runtime that mounts its routes.
            #[must_use]
            pub fn with_openapi_fragment(mut self, fragment: serde_json::Value) -> Self {
                self.0.openapi_fragments.push(fragment);
                self
            }
        }
    };
}

runtime_contribution!(
    ConsumerContractsContribution,
    "Mounted contract metadata runtime supplied by the generated root."
);
runtime_contribution!(
    WebStaticContribution,
    "Validated static-delivery runtime supplied by the generated root."
);
runtime_contribution!(
    JobsApalisRedisContribution,
    "Connected Redis/Apalis typed worker, readiness, and supervised task."
);
runtime_contribution!(
    JobsPgmqContribution,
    "Verified PGMQ typed worker, readiness, and supervised task."
);
runtime_contribution!(
    OutboxContribution,
    "Transactional outbox relay backed by a concrete publisher."
);
runtime_contribution!(
    InboxContribution,
    "Durable inbox consumers supplied by the application."
);
runtime_contribution!(
    SchedulerContribution,
    "Durable scheduler backed by a concrete envelope factory."
);
runtime_contribution!(
    EventsNatsContribution,
    "Verified JetStream consumer runtime and readiness."
);
runtime_contribution!(
    EventsRedisContribution,
    "Lossy Redis fanout ingress and listener status."
);
runtime_contribution!(
    RealtimeCoreContribution,
    "One shared realtime registry, authorization service, hub, and fanout router."
);
runtime_contribution!(SseContribution, "Authenticated SSE transport runtime.");
runtime_contribution!(
    WebSocketsContribution,
    "Authenticated WebSocket transport runtime."
);
runtime_contribution!(
    ObjectStorageContribution,
    "Connected object store with degraded health and bounded drain."
);
runtime_contribution!(
    EmailContribution,
    "Connected email delivery provider and readiness."
);
runtime_contribution!(
    NotificationsContribution,
    "Notification recovery and delivery orchestration."
);
runtime_contribution!(
    WebhooksSvixContribution,
    "Svix delivery runtime with durable replay admission."
);
runtime_contribution!(
    WebhooksInboundContribution,
    "Verified inbound provider adapters, handlers, callback router, and processor."
);
runtime_contribution!(
    FeatureFlagsContribution,
    "Feature provider and durable exposure recorder."
);
runtime_contribution!(
    OidcIdentityContribution,
    "OIDC start/callback routes and bounded pending-authorization cleanup."
);
runtime_contribution!(
    WebAuthnIdentityContribution,
    "Protected passkey registration and authentication routes."
);
runtime_contribution!(
    TotpIdentityContribution,
    "Protected TOTP enrollment, confirmation, and disable routes."
);
runtime_contribution!(
    McpCoreContribution,
    "Canonical MCP registry, dispatch, exposure filter, and trusted context resolvers."
);
runtime_contribution!(
    McpHttpContribution,
    "Authenticated MCP HTTP server, readiness, and drain runtime."
);
runtime_contribution!(
    McpStdioContribution,
    "Trusted-local MCP stdio adapter and bounded drain runtime."
);
runtime_contribution!(
    McpAuthOauthContribution,
    "OAuth protected-resource metadata mounted with bearer authentication."
);
runtime_contribution!(
    McpSubscriptionsLocalContribution,
    "Local MCP subscription service and its sole supervised receiver."
);
runtime_contribution!(
    McpSubscriptionsRedisContribution,
    "Redis MCP subscription service and its sole supervised receiver."
);
runtime_contribution!(
    McpSubscriptionsNatsContribution,
    "NATS MCP subscription service and its sole supervised receiver."
);
runtime_contribution!(
    McpTasksContribution,
    "Durable MCP task repository, typed worker bridge, and expiry runtime."
);
runtime_contribution!(
    LlmProviderRigContribution,
    "Configured Rig provider bindings and readiness."
);
runtime_contribution!(
    LlmProviderBedrockContribution,
    "Configured Bedrock provider binding and readiness."
);
runtime_contribution!(
    LlmProviderVertexContribution,
    "Configured Vertex provider binding and readiness."
);
runtime_contribution!(
    LlmRoutingContribution,
    "Provider-neutral LLM runtime, immutable routes, and readiness."
);
runtime_contribution!(
    LlmToolRuntimeContribution,
    "Authorized and audited LLM tool runtime."
);
runtime_contribution!(
    LlmMediaContribution,
    "Authorized media workflow and reconciliation runtime."
);
runtime_contribution!(
    LlmHttpApiContribution,
    "Authenticated LLM HTTP state with concrete budget, jobs, conversation, tool, and media ports."
);
runtime_contribution!(
    LlmEvalsContribution,
    "Persistent evaluation repository and operator runtime."
);

macro_rules! contribution_setter {
    ($method:ident, $field:ident, $type:ident) => {
        #[doc = concat!("Supplies the typed `", stringify!($field), "` runtime.")]
        #[must_use]
        pub fn $method(mut self, contribution: $type) -> Self {
            self.$field = Some(contribution);
            self
        }
    };
}

/// Application-owned typed domain ports supplied to selected module registrars.
///
/// Each field has a distinct type and setter. There is deliberately no
/// string-keyed escape hatch and no default provider, handler, authorizer, or
/// policy implementation.
#[derive(Default)]
pub struct ApplicationContributions {
    example_router: Option<Router>,
    example_rate_limit: Option<ExampleRateLimitConfig>,
    #[cfg(feature = "postgres")]
    postgres_pool: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "outbound-http")]
    outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
    #[cfg(feature = "idempotency")]
    api_runtime: Option<ApiRuntime>,
    consumer_contracts: Option<ConsumerContractsContribution>,
    web_static: Option<WebStaticContribution>,
    jobs_apalis_redis: Option<JobsApalisRedisContribution>,
    jobs_pgmq: Option<JobsPgmqContribution>,
    outbox: Option<OutboxContribution>,
    inbox: Option<InboxContribution>,
    scheduler: Option<SchedulerContribution>,
    events_nats: Option<EventsNatsContribution>,
    events_redis: Option<EventsRedisContribution>,
    realtime_core: Option<RealtimeCoreContribution>,
    sse: Option<SseContribution>,
    websockets: Option<WebSocketsContribution>,
    object_storage: Option<ObjectStorageContribution>,
    email: Option<EmailContribution>,
    notifications: Option<NotificationsContribution>,
    webhooks_svix: Option<WebhooksSvixContribution>,
    webhooks_inbound: Option<WebhooksInboundContribution>,
    feature_flags: Option<FeatureFlagsContribution>,
    auth_oidc: Option<OidcIdentityContribution>,
    auth_webauthn: Option<WebAuthnIdentityContribution>,
    auth_totp: Option<TotpIdentityContribution>,
    mcp_core: Option<McpCoreContribution>,
    mcp_http: Option<McpHttpContribution>,
    mcp_stdio: Option<McpStdioContribution>,
    mcp_auth_oauth: Option<McpAuthOauthContribution>,
    mcp_subscriptions_local: Option<McpSubscriptionsLocalContribution>,
    mcp_subscriptions_redis: Option<McpSubscriptionsRedisContribution>,
    mcp_subscriptions_nats: Option<McpSubscriptionsNatsContribution>,
    mcp_tasks: Option<McpTasksContribution>,
    llm_provider_rig: Option<LlmProviderRigContribution>,
    llm_provider_bedrock: Option<LlmProviderBedrockContribution>,
    llm_provider_vertex: Option<LlmProviderVertexContribution>,
    llm_routing: Option<LlmRoutingContribution>,
    llm_tool_runtime: Option<LlmToolRuntimeContribution>,
    llm_media: Option<LlmMediaContribution>,
    llm_http_api: Option<LlmHttpApiContribution>,
    llm_evals: Option<LlmEvalsContribution>,
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

    contribution_setter!(
        with_consumer_contracts,
        consumer_contracts,
        ConsumerContractsContribution
    );
    contribution_setter!(with_web_static, web_static, WebStaticContribution);
    contribution_setter!(
        with_jobs_apalis_redis,
        jobs_apalis_redis,
        JobsApalisRedisContribution
    );
    contribution_setter!(with_jobs_pgmq, jobs_pgmq, JobsPgmqContribution);
    contribution_setter!(with_outbox, outbox, OutboxContribution);
    contribution_setter!(with_inbox, inbox, InboxContribution);
    contribution_setter!(with_scheduler, scheduler, SchedulerContribution);
    contribution_setter!(with_events_nats, events_nats, EventsNatsContribution);
    contribution_setter!(
        with_events_redis,
        events_redis,
        EventsRedisContribution
    );
    contribution_setter!(
        with_realtime_core,
        realtime_core,
        RealtimeCoreContribution
    );
    contribution_setter!(with_sse, sse, SseContribution);
    contribution_setter!(with_websockets, websockets, WebSocketsContribution);
    contribution_setter!(
        with_object_storage,
        object_storage,
        ObjectStorageContribution
    );
    contribution_setter!(with_email, email, EmailContribution);
    contribution_setter!(
        with_notifications,
        notifications,
        NotificationsContribution
    );
    contribution_setter!(
        with_webhooks_svix,
        webhooks_svix,
        WebhooksSvixContribution
    );
    contribution_setter!(
        with_webhooks_inbound,
        webhooks_inbound,
        WebhooksInboundContribution
    );
    contribution_setter!(
        with_feature_flags,
        feature_flags,
        FeatureFlagsContribution
    );
    contribution_setter!(with_auth_oidc, auth_oidc, OidcIdentityContribution);
    contribution_setter!(
        with_auth_webauthn,
        auth_webauthn,
        WebAuthnIdentityContribution
    );
    contribution_setter!(with_auth_totp, auth_totp, TotpIdentityContribution);
    contribution_setter!(with_mcp_core, mcp_core, McpCoreContribution);
    contribution_setter!(with_mcp_http, mcp_http, McpHttpContribution);
    contribution_setter!(with_mcp_stdio, mcp_stdio, McpStdioContribution);
    contribution_setter!(
        with_mcp_auth_oauth,
        mcp_auth_oauth,
        McpAuthOauthContribution
    );
    contribution_setter!(
        with_mcp_subscriptions_local,
        mcp_subscriptions_local,
        McpSubscriptionsLocalContribution
    );
    contribution_setter!(
        with_mcp_subscriptions_redis,
        mcp_subscriptions_redis,
        McpSubscriptionsRedisContribution
    );
    contribution_setter!(
        with_mcp_subscriptions_nats,
        mcp_subscriptions_nats,
        McpSubscriptionsNatsContribution
    );
    contribution_setter!(with_mcp_tasks, mcp_tasks, McpTasksContribution);
    contribution_setter!(
        with_llm_provider_rig,
        llm_provider_rig,
        LlmProviderRigContribution
    );
    contribution_setter!(
        with_llm_provider_bedrock,
        llm_provider_bedrock,
        LlmProviderBedrockContribution
    );
    contribution_setter!(
        with_llm_provider_vertex,
        llm_provider_vertex,
        LlmProviderVertexContribution
    );
    contribution_setter!(
        with_llm_routing,
        llm_routing,
        LlmRoutingContribution
    );
    contribution_setter!(
        with_llm_tool_runtime,
        llm_tool_runtime,
        LlmToolRuntimeContribution
    );
    contribution_setter!(with_llm_media, llm_media, LlmMediaContribution);
    contribution_setter!(
        with_llm_http_api,
        llm_http_api,
        LlmHttpApiContribution
    );
    contribution_setter!(with_llm_evals, llm_evals, LlmEvalsContribution);

    fn provided_requirements(&self) -> BTreeSet<&'static str> {
        let mut provided = BTreeSet::new();
        if self.jobs_apalis_redis.is_some() || self.jobs_pgmq.is_some() {
            provided.insert("jobs.handlers");
        }
        if self.outbox.is_some() {
            provided.insert("outbox.publisher");
        }
        if self.scheduler.is_some() {
            provided.insert("scheduler.envelope-factory");
        }
        if self.inbox.is_some() {
            provided.insert("inbox.consumers");
        }
        if self.feature_flags.is_some() {
            provided.insert("feature-flags.provider");
            provided.insert("feature-flags.exposure-recorder");
        }
        if self.auth_oidc.is_some() {
            provided.insert("auth-oidc.runtime");
        }
        if self.auth_webauthn.is_some() {
            provided.insert("auth-webauthn.runtime");
        }
        if self.auth_totp.is_some() {
            provided.insert("auth-totp.runtime");
        }
        if self.webhooks_svix.is_some() {
            provided.insert("webhooks-svix.replay-admission");
        }
        if self.webhooks_inbound.is_some() {
            provided.insert("webhooks-inbound.provider-adapters");
            provided.insert("webhooks-inbound.handlers");
        }
        if self.realtime_core.is_some() {
            provided.insert("realtime.fanout-authorizer");
            provided.insert("realtime.identity-revalidator");
            provided.insert("realtime.event-handler");
        }
        if self.mcp_core.is_some() {
            provided.insert("mcp.capability-registry");
            provided.insert("mcp.local-context-resolver");
        }
        if self.mcp_http.is_some() && self.mcp_auth_oauth.is_some() {
            provided.insert("mcp.bearer-authenticator");
        }
        if self.mcp_subscriptions_local.is_some()
            || self.mcp_subscriptions_redis.is_some()
            || self.mcp_subscriptions_nats.is_some()
        {
            provided.insert("mcp.subscription-repository");
            provided.insert("mcp.subscription-authorizer");
            provided.insert("mcp.subscription-runtime");
            provided.insert("mcp.subscription-delivery");
        }
        if self.mcp_tasks.is_some() {
            provided.insert("mcp.task-payload-protector");
            provided.insert("mcp.cancellation-runtime");
            provided.insert("mcp.capability-executor");
        }
        if self.llm_routing.is_some() || self.llm_http_api.is_some() {
            provided.insert("llm.tool-authorization");
        }
        if self.llm_tool_runtime.is_some() || self.llm_http_api.is_some() {
            provided.insert("llm.tool-audit");
        }
        if self.llm_media.is_some() || self.llm_http_api.is_some() {
            provided.insert("llm.media-scanner");
            provided.insert("llm.media-authorization");
        }
        if self.llm_evals.is_some() {
            provided.insert("llm.evaluation-repository");
        }
        provided
    }
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
    provided_requirements: BTreeSet<&'static str>,
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
        let provided_requirements = contributions.provided_requirements();
        Self {
            input,
            contributions,
            provided_requirements,
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
    fn register_runtime_contribution(
        &mut self,
        module: &'static str,
        missing: &'static str,
        contribution: Option<ModuleRuntimeContribution>,
        route_ids: &'static [&'static str],
        task_ids: &'static [&'static str],
        health_ids: &'static [&'static str],
        operation_ids: &'static [&'static str],
    ) -> Result<(), CompositionError> {
        self.register_capability(module)?;
        if !self.runtime_available(module) {
            return Ok(());
        }
        let ModuleRuntimeContribution {
            router,
            health_specs,
            task_specs,
            openapi_fragments,
        } = contribution.ok_or(CompositionError::MissingContribution {
            module,
            contribution: missing,
        })?;
        match (route_ids.is_empty(), router) {
            (true, None) => {}
            (false, Some(router)) => self.register_router(router, route_ids)?,
            (false, None) => {
                return Err(CompositionError::ContractMismatch {
                    kind: "route",
                    id: route_ids[0],
                });
            }
            (true, Some(_)) => {
                return Err(CompositionError::InvalidConfiguration { module });
            }
        }
        if task_specs.len() != task_ids.len() {
            return Err(task_ids.first().map_or(
                CompositionError::InvalidConfiguration { module },
                |id| CompositionError::ContractMismatch { kind: "task", id },
            ));
        }
        if health_specs.len() != health_ids.len() {
            return Err(health_ids.first().map_or(
                CompositionError::InvalidConfiguration { module },
                |id| CompositionError::ContractMismatch { kind: "health", id },
            ));
        }
        for (id, spec) in task_ids.iter().copied().zip(task_specs) {
            self.register_task(id, spec)?;
        }
        for (id, spec) in health_ids.iter().copied().zip(health_specs) {
            self.register_health(id, spec)?;
        }
        for operation in operation_ids {
            self.register_public_operation(operation)?;
        }
        for fragment in openapi_fragments {
            self.register_openapi(fragment)?;
        }
        Ok(())
    }

    pub(crate) fn register_consumer_contracts(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.consumer_contracts.take().map(|value| value.0);
        self.register_runtime_contribution(
            "consumer-contracts",
            "contracts.runtime-metadata",
            contribution,
            &["GET /api/_meta"],
            &[],
            &[],
            &["getRuntimeMetadata"],
        )
    }

    pub(crate) fn register_web_static(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.web_static.take().map(|value| value.0);
        self.register_runtime_contribution(
            "web-static",
            "web-static.delivery",
            contribution,
            &["GET/HEAD /assets/*", "GET/HEAD <spa-fallback>"],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_jobs_apalis_redis(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .jobs_apalis_redis
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "jobs-apalis-redis",
            "jobs.handlers",
            contribution,
            &[],
            &["job-worker"],
            &["job-backend"],
            &[],
        )
    }

    pub(crate) fn register_jobs_pgmq(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.jobs_pgmq.take().map(|value| value.0);
        self.register_runtime_contribution(
            "jobs-pgmq",
            "jobs.handlers",
            contribution,
            &[],
            &["job-worker"],
            &["job-backend"],
            &[],
        )
    }

    pub(crate) fn register_outbox(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.outbox.take().map(|value| value.0);
        self.register_runtime_contribution(
            "outbox",
            "outbox.publisher",
            contribution,
            &[],
            &["outbox-relay"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_inbox(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.inbox.take().map(|value| value.0);
        self.register_runtime_contribution(
            "inbox",
            "inbox.consumers",
            contribution,
            &[],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_scheduler(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.scheduler.take().map(|value| value.0);
        self.register_runtime_contribution(
            "scheduler",
            "scheduler.envelope-factory",
            contribution,
            &[],
            &["scheduler"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_events_nats(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.events_nats.take().map(|value| value.0);
        self.register_runtime_contribution(
            "events-nats",
            "realtime.event-handler",
            contribution,
            &[],
            &["nats-consumers"],
            &["nats-jetstream"],
            &[],
        )
    }

    pub(crate) fn register_events_redis(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.events_redis.take().map(|value| value.0);
        self.register_runtime_contribution(
            "events-redis-ephemeral",
            "realtime.event-handler",
            contribution,
            &[],
            &["redis-pubsub-listener"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_realtime_core(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.realtime_core.take().map(|value| value.0);
        self.register_runtime_contribution(
            "realtime-core",
            "realtime.fanout-authorizer",
            contribution,
            &[],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_sse(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.sse.take().map(|value| value.0);
        self.register_runtime_contribution(
            "sse",
            "realtime.identity-revalidator",
            contribution,
            &["/realtime/events"],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_websockets(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.websockets.take().map(|value| value.0);
        self.register_runtime_contribution(
            "websockets",
            "realtime.identity-revalidator",
            contribution,
            &["/realtime/ws"],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_object_storage(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .object_storage
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "object-storage",
            "uploads.workflow",
            contribution,
            &[],
            &[],
            &["object-store"],
            &[],
        )
    }

    pub(crate) fn register_email(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.email.take().map(|value| value.0);
        self.register_runtime_contribution(
            "email",
            "jobs.handlers",
            contribution,
            &[],
            &[],
            &["email-provider"],
            &[],
        )
    }

    pub(crate) fn register_notifications(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.notifications.take().map(|value| value.0);
        self.register_runtime_contribution(
            "notifications",
            "outbox.publisher",
            contribution,
            &[],
            &["notification-orchestrator"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_webhooks_svix(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .webhooks_svix
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "webhooks-svix",
            "webhooks-svix.replay-admission",
            contribution,
            &[],
            &[],
            &["svix"],
            &[],
        )
    }

    pub(crate) fn register_webhooks_inbound(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .webhooks_inbound
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "webhooks-inbound",
            "webhooks-inbound.provider-adapters",
            contribution,
            &["/webhooks/inbound/{provider}"],
            &["inbound-webhook-processor"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_feature_flags(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.feature_flags.take().map(|value| value.0);
        self.register_runtime_contribution(
            "feature-flags",
            "feature-flags.provider",
            contribution,
            &[],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_auth_oidc(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.auth_oidc.take().map(|value| value.0);
        self.register_runtime_contribution(
            "auth-oidc",
            "auth-oidc.runtime",
            contribution,
            &[
                "/auth/oidc/{provider}/start",
                "/auth/oidc/{provider}/callback",
            ],
            &["oidc-pending-authorization-cleanup"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_auth_webauthn(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .auth_webauthn
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "auth-webauthn",
            "auth-webauthn.runtime",
            contribution,
            &[
                "/auth/passkeys",
                "/auth/passkeys/register/start",
                "/auth/passkeys/register/finish",
                "/auth/passkeys/authenticate/start",
                "/auth/passkeys/authenticate/finish",
            ],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_auth_totp(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.auth_totp.take().map(|value| value.0);
        self.register_runtime_contribution(
            "auth-totp",
            "auth-totp.runtime",
            contribution,
            &[
                "/auth/mfa/totp/enroll",
                "/auth/mfa/totp/confirm",
                "/auth/mfa/totp/disable",
            ],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_mcp_core(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.mcp_core.take().map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-server-core",
            "mcp.capability-registry",
            contribution,
            &[],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_mcp_http(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.mcp_http.take().map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-transport-http",
            "mcp.bearer-authenticator",
            contribution,
            &["POST /mcp"],
            &[],
            &["mcp-http-dispatch"],
            &["mcp.dispatch"],
        )
    }

    pub(crate) fn register_mcp_stdio(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.mcp_stdio.take().map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-transport-stdio",
            "mcp.local-context-resolver",
            contribution,
            &[],
            &[],
            &[],
            &[],
        )
    }

    pub(crate) fn register_mcp_auth_oauth(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.mcp_auth_oauth.take().map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-auth-oauth",
            "mcp.bearer-authenticator",
            contribution,
            &["GET /.well-known/oauth-protected-resource"],
            &[],
            &[],
            &["mcp.oauthProtectedResourceMetadata"],
        )
    }

    pub(crate) fn register_mcp_subscriptions_local(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .mcp_subscriptions_local
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-subscriptions-local",
            "mcp.subscription-repository",
            contribution,
            &[],
            &["mcp-subscription-backplane"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_mcp_subscriptions_redis(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .mcp_subscriptions_redis
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-subscriptions-redis",
            "mcp.subscription-repository",
            contribution,
            &[],
            &["mcp-subscription-backplane"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_mcp_subscriptions_nats(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .mcp_subscriptions_nats
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-subscriptions-nats",
            "mcp.subscription-repository",
            contribution,
            &[],
            &["mcp-subscription-backplane"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_mcp_tasks(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.mcp_tasks.take().map(|value| value.0);
        self.register_runtime_contribution(
            "mcp-tasks",
            "mcp.task-payload-protector",
            contribution,
            &[],
            &["mcp-task-expiry"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_llm_provider_rig(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .llm_provider_rig
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "llm-provider-rig",
            "llm.tool-authorization",
            contribution,
            &[],
            &[],
            &["configured-provider-route-availability"],
            &[],
        )
    }

    pub(crate) fn register_llm_provider_bedrock(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .llm_provider_bedrock
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "llm-provider-bedrock",
            "llm.tool-authorization",
            contribution,
            &[],
            &[],
            &["bedrock-route-availability"],
            &[],
        )
    }

    pub(crate) fn register_llm_provider_vertex(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .llm_provider_vertex
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "llm-provider-vertex",
            "llm.tool-authorization",
            contribution,
            &[],
            &[],
            &["vertex-route-availability"],
            &[],
        )
    }

    pub(crate) fn register_llm_routing(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.llm_routing.take().map(|value| value.0);
        self.register_runtime_contribution(
            "llm-routing",
            "llm.tool-authorization",
            contribution,
            &[],
            &[],
            &["required-route-availability"],
            &[],
        )
    }

    pub(crate) fn register_llm_tool_runtime(&mut self) -> Result<(), CompositionError> {
        let contribution = self
            .contributions
            .llm_tool_runtime
            .take()
            .map(|value| value.0);
        self.register_runtime_contribution(
            "llm-tool-runtime",
            "llm.tool-authorization",
            contribution,
            &[],
            &["tool-approval-expiry"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_llm_media(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.llm_media.take().map(|value| value.0);
        self.register_runtime_contribution(
            "llm-media",
            "llm.media-scanner",
            contribution,
            &[],
            &["llm-media-reconciliation"],
            &[],
            &[],
        )
    }

    pub(crate) fn register_llm_http_api(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.llm_http_api.take().map(|value| value.0);
        self.register_runtime_contribution(
            "llm-http-api",
            "llm.tool-authorization",
            contribution,
            &[
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
            ],
            &[],
            &[],
            &[
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
            ],
        )
    }

    pub(crate) fn register_llm_evals(&mut self) -> Result<(), CompositionError> {
        let contribution = self.contributions.llm_evals.take().map(|value| value.0);
        self.register_runtime_contribution(
            "llm-evals",
            "llm.evaluation-repository",
            contribution,
            &[],
            &[],
            &[],
            &[],
        )
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
                if !self.provided_requirements.contains(requirement) {
                    return Err(CompositionError::MissingContribution {
                        module: contract.module,
                        contribution: requirement,
                    });
                }
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
