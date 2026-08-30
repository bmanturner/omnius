use std::fmt;

use async_trait::async_trait;
use google_cloud_auth::credentials::{Credentials, service_account};
use omnius_config::ExposeSecret;
use omnius_llm_core::{
    LlmProvider, LlmRequest, ProviderCompletionResult, ProviderError, ProviderStream,
    RawRetentionPolicy,
};
use omnius_llm_provider_rig::{CatalogProvider, RigProvider};
use rig_vertexai::{ClientBuilder, completion::CompletionModel};

use crate::config::{
    VertexCredentialMode, VertexProviderConfig, VertexProviderConfigParts, config_error,
};

const GOOGLE_PUBLIC_UNIVERSE: &str = "googleapis.com";

/// Vertex AI completion provider backed by Rig's concrete Vertex model.
pub struct VertexProvider {
    inner: RigProvider,
}

impl VertexProvider {
    /// Builds the Rig Vertex AI client and concrete completion model.
    ///
    /// Application Default Credentials are resolved by Rig's source-verified
    /// `ClientBuilder`. Explicit service-account JSON is converted to the exact
    /// Google credentials value accepted by that builder. The public Google
    /// universe is forced for explicit keys so the key document cannot select
    /// an arbitrary service endpoint.
    ///
    /// # Errors
    ///
    /// Returns a redacted, non-retryable schema error when credential parsing
    /// or Vertex client construction fails.
    pub async fn new(config: VertexProviderConfig) -> Result<Self, ProviderError> {
        let VertexProviderConfigParts {
            project,
            location,
            model,
            credentials,
            raw_retention,
        } = config.into_parts();
        tokio::task::yield_now().await;
        let mut builder = ClientBuilder::new()
            .with_project(&project)
            .with_location(&location);
        if let VertexCredentialMode::ServiceAccountJson(secret) = credentials {
            builder = builder.with_credentials(service_account_credentials(&secret)?);
        }
        let client = builder.build().map_err(|_| config_error())?;
        let completion_model = CompletionModel::new(client, model.clone());
        let inner = RigProvider::from_companion_model(
            CatalogProvider::Vertex,
            model,
            raw_retention,
            completion_model,
            false,
        )?;
        Ok(Self { inner })
    }

    /// Validates that a canonical request can be represented without sending it.
    ///
    /// # Errors
    ///
    /// Returns the shared Rig adapter's typed unsupported, schema, or safety error.
    pub fn validate_request(&self, request: &LlmRequest) -> Result<(), ProviderError> {
        self.inner.validate_request(request)
    }

    /// Executes one real Vertex AI completion through Rig.
    ///
    /// # Errors
    ///
    /// Returns the shared Rig adapter's typed, redacted provider error.
    pub async fn complete(
        &self,
        request: &LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        self.inner.complete(request).await
    }

    /// Rejects streaming because Rig Vertex AI 0.42.0 has no streaming implementation.
    ///
    /// # Errors
    ///
    /// Always returns the shared provider's typed non-retryable
    /// `UnsupportedFeature::Streaming` error.
    pub async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        self.inner.stream(request).await
    }

    /// Returns content-free construction diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> VertexProviderDiagnostics {
        VertexProviderDiagnostics {
            provider: CatalogProvider::Vertex,
            raw_retention: self.inner.diagnostics().raw_retention(),
            streaming_supported: false,
        }
    }
}

impl fmt::Debug for VertexProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VertexProvider")
            .field("provider", &CatalogProvider::Vertex)
            .field("raw_retention", &self.inner.diagnostics().raw_retention())
            .field("streaming_supported", &false)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl LlmProvider for VertexProvider {
    async fn complete(
        &self,
        request: LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        VertexProvider::complete(self, &request).await
    }

    async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        VertexProvider::stream(self, request).await
    }
}

/// Non-secret, content-free Vertex provider construction diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VertexProviderDiagnostics {
    provider: CatalogProvider,
    raw_retention: RawRetentionPolicy,
    streaming_supported: bool,
}

impl VertexProviderDiagnostics {
    /// Returns the stable catalog provider identity.
    #[must_use]
    pub const fn provider(&self) -> CatalogProvider {
        self.provider
    }

    /// Returns the active raw provider-payload retention policy.
    #[must_use]
    pub const fn raw_retention(&self) -> RawRetentionPolicy {
        self.raw_retention
    }

    /// Reports whether this exact adapter supports streaming.
    #[must_use]
    pub const fn streaming_supported(&self) -> bool {
        self.streaming_supported
    }
}

fn service_account_credentials(
    secret: &omnius_config::SecretString,
) -> Result<Credentials, ProviderError> {
    let key = serde_json::from_str(secret.expose_secret()).map_err(|_| config_error())?;
    service_account::Builder::new(key)
        .with_universe_domain(GOOGLE_PUBLIC_UNIVERSE)
        .build()
        .map_err(|_| config_error())
}
