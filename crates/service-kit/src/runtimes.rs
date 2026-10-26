//! Application-owned runtime wrappers grouped by capability family.

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
        pub fn $method(mut self, port: std::sync::Arc<$type>) -> Self {
            self.$field = Some(port);
            self
        }
    };
}

mod access;
mod api;
mod delivery;
mod jobs;
mod mcp;
mod outputs;
mod privacy_llm;

#[cfg(any(feature = "admin", test))]
pub use access::AdminRuntime;
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
pub use access::AuthRuntime;
#[cfg(any(feature = "billing", test))]
pub use access::BillingRuntime;
#[cfg(any(feature = "feature-flags", test))]
pub use access::FeatureFlagsRuntime;
#[cfg(any(feature = "graphql", test))]
pub use api::GraphqlRuntime;
#[cfg(any(feature = "grpc", test))]
pub use api::GrpcRuntime;
#[cfg(feature = "web-static")]
pub use api::WebStaticRuntime;
#[cfg(feature = "email")]
pub use delivery::EmailRuntime;
#[cfg(any(
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    test
))]
pub use delivery::RealtimeRuntime;
#[cfg(any(feature = "search-meilisearch", test))]
pub use delivery::SearchRuntime;
#[cfg(any(feature = "object-storage", test))]
pub use delivery::UploadsRuntime;
#[cfg(any(feature = "webhooks-inbound", test))]
pub use delivery::WebhooksInboundRuntime;
#[cfg(any(feature = "webhooks-svix", test))]
pub use delivery::WebhooksSvixRuntime;
#[cfg(any(feature = "inbox", test))]
pub use jobs::InboxRuntime;
#[cfg(feature = "jobs-apalis-redis")]
pub use jobs::JobsApalisRedisRuntime;
#[cfg(feature = "jobs-pgmq")]
pub use jobs::JobsPgmqRuntime;
#[cfg(any(feature = "jobs-core", test))]
pub use jobs::JobsRuntime;
pub use jobs::JobsRuntimeError;
#[cfg(any(feature = "outbox", test))]
pub use jobs::OutboxRuntime;
#[cfg(any(feature = "scheduler", test))]
pub use jobs::SchedulerRuntime;
#[cfg(any(feature = "mcp-apps", test))]
pub use mcp::McpAppsRuntime;
#[cfg(any(feature = "mcp-transport-http", test))]
pub use mcp::McpAuthRuntime;
#[cfg(any(feature = "mcp-server-core", test))]
pub use mcp::McpCoreRuntime;
#[cfg(any(feature = "mcp-auth-enterprise", test))]
pub use mcp::McpEnterpriseRuntime;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
pub use mcp::McpSubscriptionsRuntime;
#[cfg(any(feature = "mcp-tasks", test))]
pub use mcp::McpTasksRuntime;
#[cfg(any(
    feature = "object-storage",
    feature = "email",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing",
))]
pub use outputs::HealthRuntime;
#[cfg(feature = "mcp-transport-http")]
pub use outputs::RouterHealthRuntime;
#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api",
))]
pub use outputs::RouterRuntime;
#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
pub use outputs::RouterTaskRuntime;
#[cfg(feature = "events-nats")]
pub use outputs::TaskHealthRuntime;
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
pub use outputs::TaskRuntime;
pub use outputs::{ShutdownError, ShutdownHook};
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
pub use privacy_llm::LlmRuntime;
#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
pub use privacy_llm::PrivacyRuntime;
