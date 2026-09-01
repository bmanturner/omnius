use crate::{AppCompositionBuilder, CompositionError};

#[cfg(feature = "consumer-contracts")]
pub(crate) async fn consumer_contracts(
    builder: &mut AppCompositionBuilder<'_>,
) -> Result<(), CompositionError> {
    builder.register_capability("consumer-contracts")?;
    let router = omnius_reference_api::generated_metadata_router(
        include_bytes!("../../../../contracts/capabilities.json"),
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|error| CompositionError::construction("consumer-contracts", error))?;
    builder.register_router(router, &["GET /api/_meta"])?;
    builder.register_public_operation("getRuntimeMetadata")
}

macro_rules! registrar {
    ($feature:literal, $function:ident, $method:ident) => {
        #[cfg(feature = $feature)]
        pub(crate) async fn $function(
            builder: &mut AppCompositionBuilder<'_>,
        ) -> Result<(), CompositionError> {
            builder.$method()
        }
    };
}

registrar!("web-static", web_static, register_web_static);
registrar!(
    "jobs-apalis-redis",
    jobs_apalis_redis,
    register_jobs_apalis_redis
);
registrar!("jobs-pgmq", jobs_pgmq, register_jobs_pgmq);
registrar!("outbox", outbox, register_outbox);
registrar!("inbox", inbox, register_inbox);
registrar!("scheduler", scheduler, register_scheduler);
registrar!("events-nats", events_nats, register_events_nats);
registrar!(
    "events-redis-ephemeral",
    events_redis_ephemeral,
    register_events_redis
);
registrar!("realtime-core", realtime_core, register_realtime_core);
registrar!("sse", sse, register_sse);
registrar!("websockets", websockets, register_websockets);
registrar!("object-storage", object_storage, register_object_storage);
registrar!("email", email, register_email);
registrar!("notifications", notifications, register_notifications);
registrar!("webhooks-svix", webhooks_svix, register_webhooks_svix);
registrar!(
    "webhooks-inbound",
    webhooks_inbound,
    register_webhooks_inbound
);
registrar!("feature-flags", feature_flags, register_feature_flags);
registrar!("auth-oidc", auth_oidc, register_auth_oidc);
registrar!("auth-webauthn", auth_webauthn, register_auth_webauthn);
registrar!("auth-totp", auth_totp, register_auth_totp);
registrar!("mcp-server-core", mcp_server_core, register_mcp_core);
registrar!("mcp-transport-http", mcp_transport_http, register_mcp_http);
registrar!(
    "mcp-transport-stdio",
    mcp_transport_stdio,
    register_mcp_stdio
);
registrar!("mcp-auth-oauth", mcp_auth_oauth, register_mcp_auth_oauth);
registrar!(
    "mcp-subscriptions-local",
    mcp_subscriptions_local,
    register_mcp_subscriptions_local
);
registrar!(
    "mcp-subscriptions-redis",
    mcp_subscriptions_redis,
    register_mcp_subscriptions_redis
);
registrar!(
    "mcp-subscriptions-nats",
    mcp_subscriptions_nats,
    register_mcp_subscriptions_nats
);
registrar!("mcp-tasks", mcp_tasks, register_mcp_tasks);
registrar!(
    "llm-provider-rig",
    llm_provider_rig,
    register_llm_provider_rig
);
registrar!(
    "llm-provider-bedrock",
    llm_provider_bedrock,
    register_llm_provider_bedrock
);
registrar!(
    "llm-provider-vertex",
    llm_provider_vertex,
    register_llm_provider_vertex
);
registrar!("llm-routing", llm_routing, register_llm_routing);
registrar!(
    "llm-tool-runtime",
    llm_tool_runtime,
    register_llm_tool_runtime
);
registrar!("llm-media", llm_media, register_llm_media);
registrar!("llm-http-api", llm_http_api, register_llm_http_api);
registrar!("llm-evals", llm_evals, register_llm_evals);
