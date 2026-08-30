use std::{fmt, sync::Arc};

use omnius_config::{ExposeSecret, SecretString};
use omnius_llm_core::{ProviderError, ProviderErrorKind, RawRetentionPolicy, RetryClass};
use omnius_outbound_http::OutboundHttpClients;

use crate::{CatalogProvider, DirectProvider};

/// Construction input for one direct Rig provider model.
pub struct RigProviderConfig {
    provider: DirectProvider,
    model: String,
    api_key: SecretString,
    outbound_http: Arc<OutboundHttpClients>,
    raw_retention: RawRetentionPolicy,
}

impl RigProviderConfig {
    /// Validates and owns direct-provider configuration.
    ///
    /// # Errors
    ///
    /// Returns a redacted schema error when the model or API key is empty.
    pub fn new(
        provider: DirectProvider,
        model: String,
        api_key: SecretString,
        outbound_http: Arc<OutboundHttpClients>,
        raw_retention: RawRetentionPolicy,
    ) -> Result<Self, ProviderError> {
        if model.trim().is_empty() || api_key.expose_secret().trim().is_empty() {
            return Err(ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Schema,
                RetryClass::Never,
            ));
        }
        Ok(Self {
            provider,
            model,
            api_key,
            outbound_http,
            raw_retention,
        })
    }

    /// Returns the direct provider identity.
    #[must_use]
    pub const fn provider(&self) -> DirectProvider {
        self.provider
    }

    /// Borrows the configured runtime model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns the raw payload retention policy.
    #[must_use]
    pub const fn raw_retention(&self) -> RawRetentionPolicy {
        self.raw_retention
    }

    pub(crate) fn into_parts(self) -> RigProviderConfigParts {
        RigProviderConfigParts {
            provider: self.provider,
            model: self.model,
            api_key: self.api_key,
            outbound_http: self.outbound_http,
            raw_retention: self.raw_retention,
        }
    }
}

pub(crate) struct RigProviderConfigParts {
    pub(crate) provider: DirectProvider,
    pub(crate) model: String,
    pub(crate) api_key: SecretString,
    pub(crate) outbound_http: Arc<OutboundHttpClients>,
    pub(crate) raw_retention: RawRetentionPolicy,
}

impl fmt::Debug for RigProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RigProviderConfig")
            .field("provider", &self.provider)
            .field("model", &"[REDACTED]")
            .field("api_key", &"[REDACTED]")
            .field("outbound_http", &"[INJECTED]")
            .field("raw_retention", &self.raw_retention)
            .finish()
    }
}

/// Non-secret construction and readiness evidence for a [`crate::RigProvider`].
#[derive(Clone, Eq, PartialEq)]
pub struct RigProviderDiagnostics {
    provider: CatalogProvider,
    model: String,
    raw_retention: RawRetentionPolicy,
}

impl RigProviderDiagnostics {
    pub(crate) fn new(
        provider: CatalogProvider,
        model: String,
        raw_retention: RawRetentionPolicy,
    ) -> Self {
        Self {
            provider,
            model,
            raw_retention,
        }
    }

    /// Returns the constructed provider.
    #[must_use]
    pub const fn provider(&self) -> CatalogProvider {
        self.provider
    }

    /// Borrows the configured model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns the active raw-retention policy.
    #[must_use]
    pub const fn raw_retention(&self) -> RawRetentionPolicy {
        self.raw_retention
    }
}

impl fmt::Debug for RigProviderDiagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RigProviderDiagnostics")
            .field("provider", &self.provider)
            .field("model", &"[REDACTED]")
            .field("raw_retention", &self.raw_retention)
            .finish()
    }
}
