use std::{fmt, sync::Arc};

use axum::Router;
use omnius_http::HttpShell;
use omnius_postgres::PostgresPool;
use omnius_runtime::TaskSpec;
use thiserror::Error;

use crate::{
    HandlerRegistry, HandlerRoute, InboundWebhookService, PostgresReceiptStore, ProviderAdapter,
    ProviderRegistry, ReceiveLimits, WebhookConfig, WebhookHandler, WebhookProcessor,
    processor_task, webhook_router,
};

/// Application-owned provider and domain-handler ports for inbound webhooks.
#[derive(Default)]
pub struct InboundWebhookContributions {
    provider_adapters: Vec<Arc<dyn ProviderAdapter>>,
    handlers: Vec<(HandlerRoute, Arc<dyn WebhookHandler>)>,
}

impl InboundWebhookContributions {
    /// Creates an empty contribution set that fails closed when the module is enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            provider_adapters: Vec::new(),
            handlers: Vec::new(),
        }
    }

    /// Supplies concrete production provider adapters.
    #[must_use]
    pub fn with_provider_adapters(
        mut self,
        adapters: impl IntoIterator<Item = Arc<dyn ProviderAdapter>>,
    ) -> Self {
        self.provider_adapters.extend(adapters);
        self
    }

    /// Supplies exact provider/type/version domain handlers.
    #[must_use]
    pub fn with_handlers(
        mut self,
        handlers: impl IntoIterator<Item = (HandlerRoute, Arc<dyn WebhookHandler>)>,
    ) -> Self {
        self.handlers.extend(handlers);
        self
    }
}

impl fmt::Debug for InboundWebhookContributions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundWebhookContributions")
            .field("provider_adapter_count", &self.provider_adapters.len())
            .field("handler_count", &self.handlers.len())
            .finish()
    }
}

/// Fully composed callback route and durable processor task.
pub struct InboundWebhookAssembly {
    service: InboundWebhookService,
    router: Router,
    processor_task: TaskSpec,
}

impl InboundWebhookAssembly {
    /// Composes provider-authenticated machine callbacks and durable asynchronous processing.
    ///
    /// # Errors
    ///
    /// Returns [`InboundWebhookAssemblyError::ApplicationRequired`] when selected application ports
    /// are absent, and a value-free construction error for invalid runtime policy.
    pub fn build(
        pool: PostgresPool,
        config: &WebhookConfig,
        contributions: InboundWebhookContributions,
        shell: &HttpShell,
    ) -> Result<Self, InboundWebhookAssemblyError> {
        if !config.enabled {
            return Err(InboundWebhookAssemblyError::Disabled);
        }
        if contributions.provider_adapters.is_empty() {
            return Err(InboundWebhookAssemblyError::ApplicationRequired {
                module: "webhooks-inbound",
                contribution: "webhooks-inbound.provider-adapters",
            });
        }
        if contributions.handlers.is_empty() {
            return Err(InboundWebhookAssemblyError::ApplicationRequired {
                module: "webhooks-inbound",
                contribution: "webhooks-inbound.handlers",
            });
        }

        let providers = ProviderRegistry::new(contributions.provider_adapters)
            .map_err(|_| InboundWebhookAssemblyError::InvalidProviders)?;
        config
            .validate_against_registry(&providers)
            .map_err(|_| InboundWebhookAssemblyError::InvalidConfig)?;
        let handlers = HandlerRegistry::new(contributions.handlers)
            .map_err(|_| InboundWebhookAssemblyError::InvalidHandlers)?;
        let store = PostgresReceiptStore::new(pool);
        let service = InboundWebhookService::new(
            providers,
            Arc::new(store.clone()),
            ReceiveLimits {
                max_body_bytes: config.max_body_bytes,
                max_header_count: config.max_header_count,
                max_header_bytes: config.max_header_bytes,
                max_safe_payload_bytes: config.max_safe_payload_bytes,
            },
            config.retention,
        )
        .map_err(|_| InboundWebhookAssemblyError::InvalidConfig)?;
        let processor = WebhookProcessor::new(store, Arc::new(handlers), config.processing)
            .map_err(|_| InboundWebhookAssemblyError::InvalidConfig)?;
        let processor_task =
            processor_task(processor).map_err(|_| InboundWebhookAssemblyError::InvalidTask)?;
        let router = shell.apply_machine_callbacks(webhook_router(service.clone()));

        Ok(Self {
            service,
            router,
            processor_task,
        })
    }

    /// Returns the transport-neutral receive service.
    #[must_use]
    pub const fn service(&self) -> &InboundWebhookService {
        &self.service
    }

    /// Splits the assembly into its protected router and supervised processor task.
    #[must_use]
    pub fn into_parts(self) -> (Router, TaskSpec) {
        (self.router, self.processor_task)
    }
}

impl fmt::Debug for InboundWebhookAssembly {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundWebhookAssembly")
            .field("service", &self.service)
            .field("processor_task", &self.processor_task)
            .finish_non_exhaustive()
    }
}

/// Fail-closed inbound webhook composition failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InboundWebhookAssemblyError {
    /// The runtime toggle is explicitly disabled.
    #[error("inbound webhook runtime is disabled")]
    Disabled,
    /// A selected module has no concrete application-owned port.
    #[error("module {module} requires application contribution {contribution}")]
    ApplicationRequired {
        /// Catalog module identifier.
        module: &'static str,
        /// Stable application requirement literal.
        contribution: &'static str,
    },
    /// Provider registration or uniqueness was invalid.
    #[error("inbound webhook providers are invalid")]
    InvalidProviders,
    /// Handler routes were invalid or duplicated.
    #[error("inbound webhook handlers are invalid")]
    InvalidHandlers,
    /// Runtime bounds or retention policy were invalid.
    #[error("inbound webhook configuration is invalid")]
    InvalidConfig,
    /// The compiled processor task declaration was invalid.
    #[error("inbound webhook processor task is invalid")]
    InvalidTask,
}
