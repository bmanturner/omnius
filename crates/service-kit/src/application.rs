//! Application-owned factory inputs, extension, and contribution registry.

use std::error::Error;
#[cfg(feature = "http")]
use std::{future::Future, pin::Pin};

#[cfg(any(feature = "admin", test))]
use crate::AdminRuntime;
#[cfg(feature = "http")]
use crate::ApplicationExtensionError;
use crate::ApplicationRateLimitConfig;
#[cfg(any(
    feature = "auth-password",
    feature = "auth-session-postgres",
    feature = "auth-api-key",
    feature = "auth-http",
    feature = "auth-session-redis",
    feature = "auth-oidc",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "auth-oauth-server",
    test
))]
use crate::AuthRuntime;
#[cfg(any(feature = "billing", test))]
use crate::BillingRuntime;
#[cfg(feature = "email")]
use crate::EmailRuntime;
#[cfg(any(feature = "feature-flags", test))]
use crate::FeatureFlagsRuntime;
#[cfg(any(feature = "graphql", test))]
use crate::GraphqlRuntime;
#[cfg(any(feature = "grpc", test))]
use crate::GrpcRuntime;
#[cfg(any(
    feature = "object-storage",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing"
))]
use crate::HealthRuntime;
#[cfg(any(feature = "inbox", test))]
use crate::InboxRuntime;
#[cfg(feature = "jobs-apalis-redis")]
use crate::JobsApalisRedisRuntime;
#[cfg(feature = "jobs-pgmq")]
use crate::JobsPgmqRuntime;
#[cfg(any(feature = "jobs-core", test))]
use crate::JobsRuntime;
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
use crate::LlmRuntime;
#[cfg(any(feature = "mcp-apps", test))]
use crate::McpAppsRuntime;
#[cfg(any(feature = "mcp-transport-http", test))]
use crate::McpAuthRuntime;
#[cfg(any(feature = "mcp-server-core", test))]
use crate::McpCoreRuntime;
#[cfg(any(feature = "mcp-auth-enterprise", test))]
use crate::McpEnterpriseRuntime;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
use crate::McpSubscriptionsRuntime;
#[cfg(any(feature = "mcp-tasks", test))]
use crate::McpTasksRuntime;
#[cfg(any(feature = "outbox", test))]
use crate::OutboxRuntime;
#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
use crate::PrivacyRuntime;
#[cfg(any(
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    test
))]
use crate::RealtimeRuntime;
#[cfg(feature = "mcp-transport-http")]
use crate::RouterHealthRuntime;
#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api"
))]
use crate::RouterRuntime;
#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
use crate::RouterTaskRuntime;
#[cfg(any(feature = "scheduler", test))]
use crate::SchedulerRuntime;
#[cfg(any(feature = "search-meilisearch", test))]
use crate::SearchRuntime;
#[cfg(feature = "events-nats")]
use crate::TaskHealthRuntime;
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
    feature = "llm-media"
))]
use crate::TaskRuntime;
#[cfg(any(feature = "object-storage", test))]
use crate::UploadsRuntime;
#[cfg(feature = "web-static")]
use crate::WebStaticRuntime;
#[cfg(any(feature = "webhooks-inbound", test))]
use crate::WebhooksInboundRuntime;
#[cfg(any(feature = "webhooks-svix", test))]
use crate::WebhooksSvixRuntime;
#[cfg(feature = "http")]
use crate::{ApplicationConfigError, ExpectedOperation};

/// Owned resources and configuration available to the one-shot application factory.
#[cfg(feature = "http")]
pub struct ApplicationRuntime {
    pub(crate) application_config: Option<serde_json::Value>,
    pub(crate) deployment: omnius_config::DeploymentEnvironment,
    #[cfg(feature = "postgres")]
    pub(crate) postgres_pool: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    pub(crate) idempotency_store: Option<omnius_idempotency::PostgresIdempotencyStore>,
    #[cfg(feature = "outbound-http")]
    pub(crate) outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
}

#[cfg(feature = "http")]
impl Default for ApplicationRuntime {
    fn default() -> Self {
        Self {
            application_config: Some(serde_json::Value::Object(serde_json::Map::new())),
            deployment: omnius_config::DeploymentEnvironment::Development,
            #[cfg(feature = "postgres")]
            postgres_pool: None,
            #[cfg(feature = "idempotency")]
            idempotency_store: None,
            #[cfg(feature = "outbound-http")]
            outbound_http: None,
        }
    }
}

#[cfg(feature = "http")]
impl ApplicationRuntime {
    /// Deserializes and consumes the application-owned configuration exactly once.
    ///
    /// The raw subtree is moved into Serde and is never cloned or formatted.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationConfigError::AlreadyDeserialized`] after the first call or
    /// [`ApplicationConfigError::Deserialize`] when the subtree does not match `T`.
    pub fn deserialize_application<T>(&mut self) -> Result<T, ApplicationConfigError>
    where
        T: serde::de::DeserializeOwned,
    {
        let value = self
            .application_config
            .take()
            .ok_or(ApplicationConfigError::AlreadyDeserialized)?;
        serde_json::from_value(value).map_err(ApplicationConfigError::Deserialize)
    }

    /// Returns the selected deployment environment.
    #[must_use]
    pub const fn deployment(&self) -> omnius_config::DeploymentEnvironment {
        self.deployment
    }

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

    /// Returns the selected outbound HTTP clients without constructing a second client.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationExtensionError::MissingOutboundHttpClients`] when
    /// the selected runtime did not construct outbound HTTP.
    #[cfg(feature = "outbound-http")]
    pub fn outbound_http(
        &self,
    ) -> Result<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>, ApplicationExtensionError>
    {
        self.outbound_http
            .clone()
            .ok_or(ApplicationExtensionError::MissingOutboundHttpClients)
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
    pub(crate) router: axum::Router,
    pub(crate) routes: &'static [&'static str],
    pub(crate) openapi_document: serde_json::Value,
    pub(crate) operations: &'static [ExpectedOperation],
}

#[cfg(feature = "http")]
impl ApplicationExtension {
    /// Creates a complete application HTTP boundary.
    #[must_use]
    pub fn new(
        application_router: axum::Router,
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

    /// Replaces only the document while retaining the extension's router contract.
    #[must_use]
    pub fn with_openapi_document(mut self, openapi_document: serde_json::Value) -> Self {
        self.openapi_document = openapi_document;
        self
    }

    /// Consumes the extension and returns its static `OpenAPI` document.
    #[must_use]
    pub fn into_openapi_document(self) -> serde_json::Value {
        self.openapi_document
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

/// Error returned by an asynchronous application factory.
pub type ApplicationFactoryError = Box<dyn Error + Send + Sync + 'static>;

#[cfg(feature = "http")]
type AsyncApplicationFactory = Box<
    dyn FnOnce(
            ApplicationRuntime,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ApplicationContributions, ApplicationFactoryError>>
                    + Send,
            >,
        > + Send
        + 'static,
>;

#[cfg(feature = "http")]
type ContractDocumentFactory = Box<dyn FnOnce() -> serde_json::Value + Send + 'static>;
/// Application-owned typed domain ports and their validated runtime outputs.
///
/// Port families are separate from module outputs: a router, task, health
/// check, or `OpenAPI` fragment never proves that an application policy exists.
#[derive(Default)]
pub struct ApplicationContributions {
    #[cfg(feature = "rate-limit-local")]
    pub(crate) application_rate_limit: Option<ApplicationRateLimitConfig>,
    #[cfg(feature = "http")]
    pub(crate) application_extension_factory: Option<ApplicationExtensionFactory>,
    #[cfg(feature = "http")]
    pub(crate) async_application_factory: Option<AsyncApplicationFactory>,
    #[cfg(feature = "http")]
    pub(crate) contract_document_factory: Option<ContractDocumentFactory>,
    #[cfg(feature = "http")]
    pub(crate) application_extension: Option<ApplicationExtension>,
    #[cfg(feature = "postgres")]
    pub(crate) postgres_pool: Option<omnius_postgres::PostgresPool>,
    #[cfg(feature = "idempotency")]
    pub(crate) idempotency_store: Option<omnius_idempotency::PostgresIdempotencyStore>,
    #[cfg(feature = "openapi")]
    pub(crate) openapi_config: Option<omnius_openapi::OpenApiConfig>,
    #[cfg(feature = "outbound-http")]
    pub(crate) outbound_http: Option<std::sync::Arc<omnius_outbound_http::OutboundHttpClients>>,
    #[cfg(any(feature = "admin", test))]
    pub(crate) admin: Option<AdminRuntime>,
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
    pub(crate) auth: Option<AuthRuntime>,
    #[cfg(any(feature = "billing", test))]
    pub(crate) billing: Option<BillingRuntime>,
    #[cfg(any(feature = "feature-flags", test))]
    pub(crate) feature_flags: Option<FeatureFlagsRuntime>,
    #[cfg(any(feature = "graphql", test))]
    pub(crate) graphql: Option<GraphqlRuntime>,
    #[cfg(any(feature = "grpc", test))]
    pub(crate) grpc: Option<GrpcRuntime>,
    #[cfg(any(feature = "inbox", test))]
    pub(crate) inbox: Option<InboxRuntime>,
    #[cfg(any(feature = "jobs-core", test))]
    pub(crate) jobs: Option<JobsRuntime>,
    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        test
    ))]
    pub(crate) llm: Option<LlmRuntime>,
    #[cfg(any(feature = "mcp-apps", test))]
    pub(crate) mcp_apps: Option<McpAppsRuntime>,
    #[cfg(any(feature = "mcp-transport-http", test))]
    pub(crate) mcp_auth: Option<McpAuthRuntime>,
    #[cfg(any(feature = "mcp-server-core", test))]
    pub(crate) mcp_core: Option<McpCoreRuntime>,
    #[cfg(any(feature = "mcp-auth-enterprise", test))]
    pub(crate) mcp_enterprise: Option<McpEnterpriseRuntime>,
    #[cfg(any(
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        test
    ))]
    pub(crate) mcp_subscriptions: Option<McpSubscriptionsRuntime>,
    #[cfg(any(feature = "mcp-tasks", test))]
    pub(crate) mcp_tasks: Option<McpTasksRuntime>,
    #[cfg(any(feature = "outbox", test))]
    pub(crate) outbox: Option<OutboxRuntime>,
    #[cfg(any(
        feature = "data-lifecycle",
        feature = "consent",
        feature = "moderation",
        test
    ))]
    pub(crate) privacy: Option<PrivacyRuntime>,
    #[cfg(any(
        feature = "redis-core",
        feature = "events-nats",
        feature = "realtime-core",
        test
    ))]
    pub(crate) realtime: Option<RealtimeRuntime>,
    #[cfg(any(feature = "scheduler", test))]
    pub(crate) scheduler: Option<SchedulerRuntime>,
    #[cfg(any(feature = "search-meilisearch", test))]
    pub(crate) search: Option<SearchRuntime>,
    #[cfg(any(feature = "object-storage", test))]
    pub(crate) uploads: Option<UploadsRuntime>,
    #[cfg(any(feature = "webhooks-inbound", test))]
    pub(crate) webhooks_inbound: Option<WebhooksInboundRuntime>,
    #[cfg(any(feature = "webhooks-svix", test))]
    pub(crate) webhooks_svix: Option<WebhooksSvixRuntime>,
    #[cfg(feature = "web-static")]
    pub(crate) web_static_output: Option<WebStaticRuntime>,
    #[cfg(feature = "jobs-apalis-redis")]
    pub(crate) jobs_apalis_redis_output: Option<JobsApalisRedisRuntime>,
    #[cfg(feature = "jobs-pgmq")]
    pub(crate) jobs_pgmq_output: Option<JobsPgmqRuntime>,
    #[cfg(feature = "outbox")]
    pub(crate) outbox_output: Option<TaskRuntime>,
    #[cfg(feature = "scheduler")]
    pub(crate) scheduler_output: Option<TaskRuntime>,
    #[cfg(feature = "events-nats")]
    pub(crate) events_nats_output: Option<TaskHealthRuntime>,
    #[cfg(feature = "events-redis-ephemeral")]
    pub(crate) events_redis_output: Option<TaskRuntime>,
    #[cfg(feature = "sse")]
    pub(crate) sse_output: Option<RouterRuntime>,
    #[cfg(feature = "websockets")]
    pub(crate) websockets_output: Option<RouterRuntime>,
    #[cfg(feature = "object-storage")]
    pub(crate) object_storage_output: Option<HealthRuntime>,
    #[cfg(feature = "email")]
    pub(crate) email_output: Option<EmailRuntime>,
    #[cfg(feature = "notifications")]
    pub(crate) notifications_output: Option<TaskRuntime>,
    #[cfg(feature = "webhooks-svix")]
    pub(crate) webhooks_svix_output: Option<HealthRuntime>,
    #[cfg(feature = "webhooks-inbound")]
    pub(crate) webhooks_inbound_output: Option<RouterTaskRuntime>,
    #[cfg(feature = "auth-oidc")]
    pub(crate) auth_oidc_output: Option<RouterTaskRuntime>,
    #[cfg(feature = "auth-webauthn")]
    pub(crate) auth_webauthn_output: Option<RouterRuntime>,
    #[cfg(feature = "auth-totp")]
    pub(crate) auth_totp_output: Option<RouterRuntime>,
    #[cfg(feature = "mcp-transport-http")]
    pub(crate) mcp_http_output: Option<RouterHealthRuntime>,
    #[cfg(feature = "mcp-auth-oauth")]
    pub(crate) mcp_auth_oauth_output: Option<RouterRuntime>,
    #[cfg(feature = "mcp-subscriptions-local")]
    pub(crate) mcp_subscriptions_local_output: Option<TaskRuntime>,
    #[cfg(feature = "mcp-subscriptions-redis")]
    pub(crate) mcp_subscriptions_redis_output: Option<TaskRuntime>,
    #[cfg(feature = "mcp-subscriptions-nats")]
    pub(crate) mcp_subscriptions_nats_output: Option<TaskRuntime>,
    #[cfg(feature = "mcp-tasks")]
    pub(crate) mcp_tasks_output: Option<TaskRuntime>,
    #[cfg(feature = "llm-provider-rig")]
    pub(crate) llm_provider_rig_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-provider-bedrock")]
    pub(crate) llm_provider_bedrock_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-provider-vertex")]
    pub(crate) llm_provider_vertex_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-routing")]
    pub(crate) llm_routing_output: Option<HealthRuntime>,
    #[cfg(feature = "llm-tool-runtime")]
    pub(crate) llm_tool_runtime_output: Option<TaskRuntime>,
    #[cfg(feature = "llm-media")]
    pub(crate) llm_media_output: Option<TaskRuntime>,
    #[cfg(feature = "llm-http-api")]
    pub(crate) llm_http_api_output: Option<RouterRuntime>,
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

    /// Supplies an additive one-shot asynchronous application factory.
    ///
    /// The returned contribution set may replace the default application
    /// extension and supply concrete auth, jobs, and email runtimes.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn with_application_factory<F, Fut>(mut self, factory: F) -> Self
    where
        F: FnOnce(ApplicationRuntime) -> Fut + Send + 'static,
        Fut: Future<Output = Result<ApplicationContributions, ApplicationFactoryError>>
            + Send
            + 'static,
    {
        self.async_application_factory = Some(Box::new(move |runtime| Box::pin(factory(runtime))));
        self
    }

    /// Supplies the concrete application extension built by an asynchronous factory.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn with_application_extension_runtime(
        mut self,
        application_extension: ApplicationExtension,
    ) -> Self {
        self.application_extension = Some(application_extension);
        self
    }

    /// Supplies a static application contract without constructing runtime resources.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn with_contract_document<F>(mut self, factory: F) -> Self
    where
        F: FnOnce() -> serde_json::Value + Send + 'static,
    {
        self.contract_document_factory = Some(Box::new(factory));
        self
    }

    /// Consumes the optional static application contract contribution.
    #[cfg(feature = "http")]
    pub fn take_contract_document(&mut self) -> Option<serde_json::Value> {
        self.contract_document_factory
            .take()
            .map(|factory| factory())
    }

    runtime_setter!(any(feature = "admin", test); with_admin_runtime, admin, AdminRuntime);
    runtime_setter!(
        any(
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
    runtime_setter!(feature = "email"; with_email_output, email_output, EmailRuntime);
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
