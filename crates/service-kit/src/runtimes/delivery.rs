//! Application-owned realtime, upload, webhook, search, and email runtime wrappers.

#[cfg(feature = "email")]
use crate::ShutdownHook;
#[cfg(any(
    feature = "redis-core",
    feature = "events-nats",
    feature = "realtime-core",
    test
))]
use crate::ports::RealtimeEventHandlerPort;
#[cfg(any(feature = "realtime-core", test))]
use crate::ports::RealtimeFanoutAuthorizerPort;
#[cfg(any(feature = "realtime-core", test))]
use crate::ports::RealtimeIdentityRevalidatorPort;
#[cfg(any(feature = "search-meilisearch", test))]
use crate::ports::SearchIndexSchemaPort;
#[cfg(any(feature = "search-meilisearch", test))]
use crate::ports::SearchProjectionResolverPort;
#[cfg(any(feature = "search-meilisearch", test))]
use crate::ports::SearchReauthorizerPort;
#[cfg(any(feature = "object-storage", test))]
use crate::ports::UploadAuthorizationPort;
#[cfg(any(feature = "object-storage", test))]
use crate::ports::UploadWorkflowPort;
#[cfg(any(feature = "webhooks-inbound", test))]
use crate::ports::WebhooksInboundHandlersPort;
#[cfg(any(feature = "webhooks-inbound", test))]
use crate::ports::WebhooksInboundProviderAdaptersPort;
#[cfg(any(feature = "webhooks-svix", test))]
use crate::ports::WebhooksSvixReplayAdmissionPort;

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
    pub(crate) fanout_authorizer: Option<std::sync::Arc<dyn RealtimeFanoutAuthorizerPort>>,
    #[cfg(any(feature = "realtime-core", test))]
    pub(crate) identity_revalidator: Option<std::sync::Arc<dyn RealtimeIdentityRevalidatorPort>>,
    #[cfg(any(
        feature = "redis-core",
        feature = "events-nats",
        feature = "realtime-core",
        test
    ))]
    pub(crate) event_handler: Option<std::sync::Arc<dyn RealtimeEventHandlerPort>>,
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
    pub(crate) workflow: Option<std::sync::Arc<dyn UploadWorkflowPort>>,
    pub(crate) authorization: Option<std::sync::Arc<dyn UploadAuthorizationPort>>,
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
    pub(crate) provider_adapters: Option<std::sync::Arc<dyn WebhooksInboundProviderAdaptersPort>>,
    pub(crate) handlers: Option<std::sync::Arc<dyn WebhooksInboundHandlersPort>>,
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
    pub(crate) replay_admission: Option<std::sync::Arc<dyn WebhooksSvixReplayAdmissionPort>>,
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
    pub(crate) index_schema: Option<std::sync::Arc<dyn SearchIndexSchemaPort>>,
    pub(crate) reauthorizer: Option<std::sync::Arc<dyn SearchReauthorizerPort>>,
    pub(crate) projection_resolver: Option<std::sync::Arc<dyn SearchProjectionResolverPort>>,
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

/// Concrete email lifecycle output.
#[cfg(feature = "email")]
pub struct EmailRuntime {
    pub(crate) health: omnius_health::HealthCheckSpec,
    pub(crate) shutdown: ShutdownHook,
}

#[cfg(feature = "email")]
impl EmailRuntime {
    /// Builds email health and shutdown outputs from authenticated HTTP.
    #[cfg(feature = "auth-http")]
    #[must_use]
    pub fn from_authenticated_http(runtime: &omnius_auth_http::AuthenticatedHttpRuntime) -> Self {
        let email = runtime.email().clone();
        Self {
            health: runtime.email_health_check(),
            shutdown: ShutdownHook::new("email-provider", move || async move {
                email.shutdown().await;
                Ok(())
            }),
        }
    }

    /// Creates explicit email lifecycle outputs.
    #[must_use]
    pub fn new(health: omnius_health::HealthCheckSpec, shutdown: ShutdownHook) -> Self {
        Self { health, shutdown }
    }
}
