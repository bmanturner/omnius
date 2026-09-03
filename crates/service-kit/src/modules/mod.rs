#[cfg(feature = "config")]
pub(crate) mod config;
#[cfg(feature = "core")]
pub(crate) mod core;
#[cfg(feature = "health")]
pub(crate) mod health;
#[cfg(feature = "http")]
pub(crate) mod http;
#[cfg(feature = "idempotency")]
pub(crate) mod idempotency;
#[cfg(feature = "migrations")]
pub(crate) mod migrations;
#[cfg(feature = "openapi")]
pub(crate) mod openapi;
#[cfg(feature = "outbound-http")]
pub(crate) mod outbound_http;
#[cfg(feature = "postgres")]
pub(crate) mod postgres;
#[cfg(feature = "rate-limit-local")]
pub(crate) mod rate_limit_local;
#[cfg(feature = "runtime")]
pub(crate) mod runtime;
#[cfg(feature = "telemetry")]
pub(crate) mod telemetry;

mod family;

macro_rules! family_module {
    ($feature:literal, $module:ident, $register:ident) => {
        #[cfg(feature = $feature)]
        pub(crate) mod $module {
            pub(crate) use super::family::$register as register;
        }
    };
}

family_module!("web-static", web_static, web_static);
family_module!("jobs-apalis-redis", jobs_apalis_redis, jobs_apalis_redis);
family_module!("jobs-pgmq", jobs_pgmq, jobs_pgmq);
family_module!("outbox", outbox, outbox);
family_module!("inbox", inbox, inbox);
family_module!("scheduler", scheduler, scheduler);
family_module!("events-nats", events_nats, events_nats);
family_module!(
    "events-redis-ephemeral",
    events_redis_ephemeral,
    events_redis_ephemeral
);
family_module!("realtime-core", realtime_core, realtime_core);
family_module!("sse", sse, sse);
family_module!("websockets", websockets, websockets);
family_module!("object-storage", object_storage, object_storage);
family_module!("email", email, email);
family_module!("notifications", notifications, notifications);
family_module!("webhooks-svix", webhooks_svix, webhooks_svix);
family_module!("webhooks-inbound", webhooks_inbound, webhooks_inbound);
family_module!("feature-flags", feature_flags, feature_flags);
family_module!("auth-oidc", auth_oidc, auth_oidc);
family_module!("auth-webauthn", auth_webauthn, auth_webauthn);
family_module!("auth-totp", auth_totp, auth_totp);
family_module!("mcp-server-core", mcp_server_core, mcp_server_core);
family_module!("mcp-transport-http", mcp_transport_http, mcp_transport_http);
family_module!("mcp-auth-oauth", mcp_auth_oauth, mcp_auth_oauth);
family_module!(
    "mcp-subscriptions-local",
    mcp_subscriptions_local,
    mcp_subscriptions_local
);
family_module!(
    "mcp-subscriptions-redis",
    mcp_subscriptions_redis,
    mcp_subscriptions_redis
);
family_module!(
    "mcp-subscriptions-nats",
    mcp_subscriptions_nats,
    mcp_subscriptions_nats
);
family_module!("mcp-tasks", mcp_tasks, mcp_tasks);
family_module!("llm-provider-rig", llm_provider_rig, llm_provider_rig);
family_module!(
    "llm-provider-bedrock",
    llm_provider_bedrock,
    llm_provider_bedrock
);
family_module!(
    "llm-provider-vertex",
    llm_provider_vertex,
    llm_provider_vertex
);
family_module!("llm-routing", llm_routing, llm_routing);
family_module!("llm-tool-runtime", llm_tool_runtime, llm_tool_runtime);
family_module!("llm-media", llm_media, llm_media);
family_module!("llm-http-api", llm_http_api, llm_http_api);
