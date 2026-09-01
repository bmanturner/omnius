use std::{fmt, time::Duration};

use omnius_config::DeploymentEnvironment;
use omnius_health::HealthCheckSpec;
use omnius_outbound_http::OutboundUrlPolicy;

use crate::{BlobStore, BlobStoreError, ObjectStorageConfig, object_store_health_check};

/// Concrete object store with its degraded health declaration and ordered lifecycle controls.
pub struct ObjectStorageAssembly {
    store: BlobStore,
    health_check: HealthCheckSpec,
}

impl ObjectStorageAssembly {
    /// Builds the selected provider through the central outbound URL policy.
    ///
    /// # Errors
    ///
    /// Returns [`BlobStoreError`] for unsafe configuration, forbidden topology, credentials, or
    /// provider construction failure.
    pub async fn build(
        config: ObjectStorageConfig,
        environment: DeploymentEnvironment,
        url_policy: &OutboundUrlPolicy,
        health_timeout: Duration,
    ) -> Result<Self, BlobStoreError> {
        let store = BlobStore::build(config, environment, url_policy).await?;
        let health_check = object_store_health_check(store.clone(), health_timeout);
        Ok(Self {
            store,
            health_check,
        })
    }

    /// Returns the tenant-scoped storage port.
    #[must_use]
    pub const fn store(&self) -> &BlobStore {
        &self.store
    }

    /// Returns the degraded provider health declaration.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        self.health_check.clone()
    }

    /// Closes admission while allowing already-admitted streams to finish.
    pub fn begin_drain(&self) {
        self.store.begin_drain();
    }

    /// Cancels all outstanding storage work after the application drain bound expires.
    pub fn shutdown(&self) {
        self.store.shutdown();
    }
}

impl fmt::Debug for ObjectStorageAssembly {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStorageAssembly")
            .field("status", &self.store.status())
            .field("health_check", &self.health_check)
            .finish_non_exhaustive()
    }
}
