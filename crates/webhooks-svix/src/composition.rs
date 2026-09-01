use std::{fmt, sync::Arc, time::Duration};

use omnius_health::HealthCheckSpec;
use omnius_outbox::OutboxPublisher;
use thiserror::Error;

use crate::{
    ConfigError, ProviderError, ReplayAdmission, SvixConfig, SvixWebhookProvider, svix_health_check,
};

/// Concrete Svix provider, transactional-outbox bridge, health check, and bounded drain owner.
pub struct SvixAssembly {
    provider: Arc<SvixWebhookProvider>,
    publisher: Arc<dyn OutboxPublisher>,
    health_check: HealthCheckSpec,
}

impl SvixAssembly {
    /// Builds production Svix only when durable replay admission is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`SvixAssemblyError::ApplicationRequired`] when durable replay admission is absent,
    /// or [`SvixAssemblyError::InvalidConfig`] for invalid provider configuration.
    pub fn build(
        config: &SvixConfig,
        replay_admission: Option<Arc<dyn ReplayAdmission>>,
        health_timeout: Duration,
    ) -> Result<Self, SvixAssemblyError> {
        let replay_admission = replay_admission.ok_or(SvixAssemblyError::ApplicationRequired {
            module: "webhooks-svix",
            contribution: "webhooks-svix.replay-admission",
        })?;
        let provider = Arc::new(
            SvixWebhookProvider::new(config, replay_admission)
                .map_err(SvixAssemblyError::InvalidConfig)?,
        );
        let publisher: Arc<dyn OutboxPublisher> = provider.clone();
        let health_check = svix_health_check(provider.clone(), health_timeout);
        Ok(Self {
            provider,
            publisher,
            health_check,
        })
    }

    /// Returns the concrete provider for endpoint and replay administration.
    #[must_use]
    pub const fn provider(&self) -> &Arc<SvixWebhookProvider> {
        &self.provider
    }

    /// Returns the mandatory transactional-outbox publication bridge.
    #[must_use]
    pub fn outbox_publisher(&self) -> Arc<dyn OutboxPublisher> {
        Arc::clone(&self.publisher)
    }

    /// Returns the degraded provider health declaration.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        self.health_check.clone()
    }

    /// Stops accepting publication and replay work before task cancellation.
    pub fn begin_drain(&self) {
        self.provider.begin_shutdown();
    }

    /// Cancels admitted work and waits for the provider's bounded drain.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] when admitted operations do not drain by the configured deadline.
    pub async fn shutdown(&self) -> Result<(), ProviderError> {
        self.provider.shutdown().await
    }
}

impl fmt::Debug for SvixAssembly {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SvixAssembly")
            .field("provider", &self.provider)
            .field("health_check", &self.health_check)
            .finish_non_exhaustive()
    }
}

/// Fail-closed Svix assembly failure.
#[derive(Debug, Error)]
pub enum SvixAssemblyError {
    /// A selected module has no concrete application-owned port.
    #[error("module {module} requires application contribution {contribution}")]
    ApplicationRequired {
        /// Catalog module identifier.
        module: &'static str,
        /// Stable application requirement literal.
        contribution: &'static str,
    },
    /// Provider configuration violated a hard safety bound.
    #[error("Svix configuration is invalid")]
    InvalidConfig(#[source] ConfigError),
}
