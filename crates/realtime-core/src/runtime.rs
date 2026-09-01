use std::sync::Arc;

use omnius_authz_basic::{AuthorizationProvider, AuthorizationService};
use omnius_runtime::{ShutdownReport, SupervisorHandle};

use crate::{
    CommandAuthorizationResolver, ConnectionDeliveryHub, ConnectionRegistry, DeliveryDrainOutcome,
    DeliveryQueueConfig, FanoutAuthorizer, FanoutRouter, FanoutRouterConfig, RealtimeService,
    RegistryConfig,
};

/// One process-level realtime registry, authorization service, delivery hub, and fan-out root.
///
/// Clones of this value retain the same registry, service, and bounded delivery hub. Construct one
/// root per process and derive every transport state and provider ingress from it.
pub struct RealtimeRuntime<P, R> {
    registry: Arc<ConnectionRegistry>,
    service: Arc<RealtimeService<P, R>>,
    delivery_hub: ConnectionDeliveryHub,
}

impl<P, R> Clone for RealtimeRuntime<P, R> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
            service: Arc::clone(&self.service),
            delivery_hub: self.delivery_hub.clone(),
        }
    }
}

impl<P, R> RealtimeRuntime<P, R>
where
    P: AuthorizationProvider,
    R: CommandAuthorizationResolver,
{
    /// Creates the single process-level realtime root.
    #[must_use]
    pub fn new(
        registry_config: RegistryConfig,
        authorization: AuthorizationService<P>,
        resolver: R,
        delivery_config: DeliveryQueueConfig,
    ) -> Self {
        let registry = Arc::new(ConnectionRegistry::new(registry_config));
        let service = Arc::new(RealtimeService::new(
            registry.as_ref().clone(),
            authorization,
            resolver,
        ));
        let delivery_hub = ConnectionDeliveryHub::new(Arc::clone(&registry), delivery_config);
        Self {
            registry,
            service,
            delivery_hub,
        }
    }

    /// Returns the sole shared registry for this process.
    #[must_use]
    pub const fn registry(&self) -> &Arc<ConnectionRegistry> {
        &self.registry
    }

    /// Returns the sole shared command service for this process.
    #[must_use]
    pub const fn service(&self) -> &Arc<RealtimeService<P, R>> {
        &self.service
    }

    /// Returns the sole shared bounded delivery hub for this process.
    #[must_use]
    pub const fn delivery_hub(&self) -> &ConnectionDeliveryHub {
        &self.delivery_hub
    }

    /// Creates a fan-out router over this root's exact registry.
    #[must_use]
    pub fn fanout_router<A>(&self, authorizer: A, config: FanoutRouterConfig) -> FanoutRouter<A>
    where
        A: FanoutAuthorizer,
    {
        FanoutRouter::new(Arc::clone(&self.registry), authorizer, config)
    }

    /// Synchronously closes transport and fan-out intake before provider cancellation begins.
    pub fn begin_drain(&self) {
        self.delivery_hub.begin_drain();
    }

    /// Drains admitted transport delivery before stopping provider tasks and awaiting their resource
    /// shutdown.
    ///
    /// Every realtime provider listener, durable consumer, and resource-drain task must be registered
    /// with `supervisor`. This method intentionally does not signal that supervisor until the shared
    /// hub has completed its bounded drain, so provider cancellation cannot overtake terminal
    /// transport delivery.
    pub async fn shutdown(&self, supervisor: SupervisorHandle) -> RealtimeShutdownReport {
        self.delivery_hub.begin_drain();
        let delivery = self.delivery_hub.drain().await;
        supervisor.begin_drain();
        let providers = supervisor.shutdown().await;
        RealtimeShutdownReport {
            delivery,
            providers,
        }
    }
}

/// Result of ordered transport-first, provider-second realtime shutdown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealtimeShutdownReport {
    delivery: DeliveryDrainOutcome,
    providers: ShutdownReport,
}

impl RealtimeShutdownReport {
    /// Returns the bounded delivery drain result.
    #[must_use]
    pub const fn delivery(&self) -> DeliveryDrainOutcome {
        self.delivery
    }

    /// Returns the completed provider supervisor report.
    #[must_use]
    pub const fn providers(&self) -> &ShutdownReport {
        &self.providers
    }

    /// Consumes the report into delivery and provider results.
    #[must_use]
    pub fn into_parts(self) -> (DeliveryDrainOutcome, ShutdownReport) {
        (self.delivery, self.providers)
    }
}
