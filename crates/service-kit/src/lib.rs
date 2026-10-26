//! Static application composition for generated services.

pub use omnius_core::{
    BuildMetadata, BuildMetadataInput, Clock, ErrorCode, InvalidBuildMetadata, ProviderMetadata,
    RequestId, SchemaCompatibility, ServiceError, SystemClock,
};

#[cfg(feature = "http")]
pub use omnius_http::ExpectedOperation;

mod application;
#[cfg(any(feature = "core", test))]
mod builder;
mod catalog;
mod composed;
mod composition;
mod facade;
mod modules;
mod ports;
mod runtimes;
mod selected_runtime;
pub use application::{ApplicationContributions, ApplicationFactoryError};
#[cfg(feature = "http")]
pub use application::{ApplicationExtension, ApplicationRuntime};
#[cfg(any(feature = "core", test))]
pub use builder::AppCompositionBuilder;
pub use catalog::{ApplicationRequirement, SelectedModuleContract};
pub use composed::{ComposedApplication, RuntimeParts};
pub use composition::{
    ApplicationConfigError, ApplicationExtensionError, ApplicationRateLimitConfig,
    CompositionCriticality, CompositionError, CompositionInput,
    selected_requires_application_contributions,
};
#[cfg(feature = "auth-core")]
pub use facade::auth;
#[cfg(feature = "auth-http")]
pub use facade::auth_http;
#[cfg(feature = "http")]
pub use facade::http;
#[cfg(feature = "idempotency")]
pub use facade::idempotency;
#[cfg(feature = "openapi")]
pub use facade::openapi;
#[cfg(feature = "outbound-http")]
pub use facade::outbound_http;
#[cfg(feature = "postgres")]
pub use facade::postgres;
#[cfg(feature = "telemetry")]
pub use facade::telemetry;
#[cfg(feature = "test-support")]
pub use facade::test_support;
pub use facade::{config, health, runtime};
#[cfg(feature = "migrations")]
pub use facade::{migrate, migrations};
pub use ports::{
    AdminAuthorityResolverPort, AdminOperationHandlerPort, BillingProviderPort,
    FeatureFlagExposureRecorderPort, FeatureFlagProviderPort, GraphqlRequestDataInjectorPort,
    GraphqlSchemaPort, GrpcApplicationServicePort, GrpcAuthenticatorPort, GrpcMethodPoliciesPort,
    InboxConsumersPort, LlmEvaluationRepositoryPort, LlmMediaAuthorizationPort,
    LlmMediaScannerPort, LlmToolAuditPort, LlmToolAuthorizationPort, McpAppsPorts,
    McpBearerAuthenticatorPort, McpCancellationRuntimePort, McpCapabilityExecutorPort,
    McpCapabilityRegistryPort, McpEnterprisePorts, McpSubscriptionAuthorizerPort,
    McpSubscriptionDeliveryPort, McpSubscriptionRepositoryPort, McpSubscriptionRuntimePort,
    McpTaskPayloadProtectorPort, OauthRuntimePort, OidcRuntimePort, OutboxPublisherPort,
    PrivacyAuthorizerPort, PrivacyConsentPolicyPort, PrivacyInventoryAdaptersPort,
    PrivacyInventoryManifestPort, PrivacyLifecycleHandlerPort, PrivacyModerationPolicyPort,
    RealtimeEventHandlerPort, RealtimeFanoutAuthorizerPort, RealtimeIdentityRevalidatorPort,
    RedisSessionRuntimePort, SchedulerEnvelopeFactoryPort, SearchIndexSchemaPort,
    SearchProjectionResolverPort, SearchReauthorizerPort, TotpRuntimePort, UploadAuthorizationPort,
    UploadWorkflowPort, WebauthnRuntimePort, WebhooksInboundHandlersPort,
    WebhooksInboundProviderAdaptersPort, WebhooksSvixReplayAdmissionPort,
};
#[cfg(any(feature = "admin", test))]
pub use runtimes::AdminRuntime;
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
pub use runtimes::AuthRuntime;
#[cfg(any(feature = "billing", test))]
pub use runtimes::BillingRuntime;
#[cfg(feature = "email")]
pub use runtimes::EmailRuntime;
#[cfg(any(feature = "feature-flags", test))]
pub use runtimes::FeatureFlagsRuntime;
#[cfg(any(feature = "graphql", test))]
pub use runtimes::GraphqlRuntime;
#[cfg(any(feature = "grpc", test))]
pub use runtimes::GrpcRuntime;
#[cfg(any(
    feature = "object-storage",
    feature = "email",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing",
))]
pub use runtimes::HealthRuntime;
#[cfg(any(feature = "inbox", test))]
pub use runtimes::InboxRuntime;
#[cfg(feature = "jobs-apalis-redis")]
pub use runtimes::JobsApalisRedisRuntime;
#[cfg(feature = "jobs-pgmq")]
pub use runtimes::JobsPgmqRuntime;
#[cfg(any(feature = "jobs-core", test))]
pub use runtimes::JobsRuntime;
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
pub use runtimes::LlmRuntime;
#[cfg(any(feature = "mcp-apps", test))]
pub use runtimes::McpAppsRuntime;
#[cfg(any(feature = "mcp-transport-http", test))]
pub use runtimes::McpAuthRuntime;
#[cfg(any(feature = "mcp-server-core", test))]
pub use runtimes::McpCoreRuntime;
#[cfg(any(feature = "mcp-auth-enterprise", test))]
pub use runtimes::McpEnterpriseRuntime;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
pub use runtimes::McpSubscriptionsRuntime;
#[cfg(any(feature = "mcp-tasks", test))]
pub use runtimes::McpTasksRuntime;
#[cfg(any(feature = "outbox", test))]
pub use runtimes::OutboxRuntime;
#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
pub use runtimes::PrivacyRuntime;
#[cfg(any(
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    test
))]
pub use runtimes::RealtimeRuntime;
#[cfg(feature = "mcp-transport-http")]
pub use runtimes::RouterHealthRuntime;
#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api",
))]
pub use runtimes::RouterRuntime;
#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
pub use runtimes::RouterTaskRuntime;
#[cfg(any(feature = "scheduler", test))]
pub use runtimes::SchedulerRuntime;
#[cfg(any(feature = "search-meilisearch", test))]
pub use runtimes::SearchRuntime;
#[cfg(feature = "events-nats")]
pub use runtimes::TaskHealthRuntime;
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
pub use runtimes::TaskRuntime;
#[cfg(any(feature = "object-storage", test))]
pub use runtimes::UploadsRuntime;
#[cfg(feature = "web-static")]
pub use runtimes::WebStaticRuntime;
#[cfg(any(feature = "webhooks-inbound", test))]
pub use runtimes::WebhooksInboundRuntime;
#[cfg(any(feature = "webhooks-svix", test))]
pub use runtimes::WebhooksSvixRuntime;
pub use runtimes::{JobsRuntimeError, ShutdownError, ShutdownHook};
pub use selected_runtime::{
    MigrationStatusDocument, SelectedMigrationCommand, SelectedRuntime, SelectedRuntimeConfig,
    execute_selected_migration,
};

#[cfg(test)]
mod contract_tests;
