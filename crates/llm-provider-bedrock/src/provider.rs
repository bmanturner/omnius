use std::fmt;

use async_trait::async_trait;
use aws_sdk_bedrockruntime::{Client as AwsBedrockRuntimeClient, config::Region};
use omnius_config::ExposeSecret as _;
use omnius_llm_core::{
    LlmProvider, LlmRequest, ProviderCompletionResult, ProviderError, ProviderStream,
    RawRetentionPolicy,
};
use omnius_llm_provider_rig::{CatalogProvider, RigProvider};
use rig_bedrock::{
    client::{Client, ClientBuilder},
    completion::CompletionModel,
};

use crate::{BedrockCredentialMode, BedrockProviderConfig, config::BedrockProviderConfigParts};

/// AWS Bedrock completion and streaming provider with SDK values kept private.
pub struct BedrockProvider {
    inner: RigProvider,
    diagnostics: BedrockProviderDiagnostics,
}

impl BedrockProvider {
    /// Resolves AWS credentials, constructs the Bedrock client and concrete Rig
    /// completion model, and installs the shared canonical provider driver.
    ///
    /// The AWS SDK may consult its standard credential sources while resolving
    /// the default chain or named profile. No model operation is sent during
    /// construction. Configured endpoint URLs are removed before the runtime
    /// client is installed, preserving the SDK's regional endpoint resolver.
    ///
    /// # Errors
    ///
    /// Returns a typed, content-free schema error if the shared Rig companion
    /// seam rejects construction.
    pub async fn new(config: BedrockProviderConfig) -> Result<Self, ProviderError> {
        let BedrockProviderConfigParts {
            region,
            model,
            credentials,
            raw_retention,
            streaming_supported,
        } = config.into_parts();
        let client = build_client(&region, credentials).await;
        let completion_model = CompletionModel::new(client, model.clone());
        let inner = RigProvider::from_companion_model(
            CatalogProvider::Bedrock,
            model,
            raw_retention,
            completion_model,
            streaming_supported,
        )?;
        Ok(Self {
            inner,
            diagnostics: BedrockProviderDiagnostics::configured(raw_retention, streaming_supported),
        })
    }

    /// Validates that the canonical request can be represented without sending it.
    ///
    /// # Errors
    ///
    /// Returns the shared typed unsupported, schema, or safety error for the
    /// first rejected semantic.
    pub fn validate_request(&self, request: &LlmRequest) -> Result<(), ProviderError> {
        self.inner.validate_request(request)
    }

    /// Executes one canonical non-streaming completion through Bedrock Converse.
    ///
    /// # Errors
    ///
    /// Returns the shared typed and redacted provider, transport, timeout,
    /// throttling, safety, unsupported, or schema error.
    pub async fn complete(
        &self,
        request: &LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        self.inner.complete(request).await
    }

    /// Opens one bounded canonical stream through Bedrock `ConverseStream`.
    ///
    /// # Errors
    ///
    /// Returns the shared typed and redacted error when request conversion or
    /// provider stream establishment fails.
    pub async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        self.inner.stream(request).await
    }

    /// Returns content-free construction and route-readiness evidence.
    #[must_use]
    pub const fn diagnostics(&self) -> BedrockProviderDiagnostics {
        self.diagnostics
    }
}

impl fmt::Debug for BedrockProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BedrockProvider")
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl LlmProvider for BedrockProvider {
    async fn complete(
        &self,
        request: LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        BedrockProvider::complete(self, &request).await
    }

    async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        BedrockProvider::stream(self, request).await
    }
}

/// Value-free Bedrock construction and route-readiness evidence.
///
/// A value is available only after configuration validation, AWS credential
/// source loading, endpoint-override removal, concrete model construction, and
/// shared-driver construction have completed. It does not claim that AWS has
/// authenticated a request or that a particular model is enabled in the account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BedrockProviderDiagnostics {
    raw_retention: RawRetentionPolicy,
    streaming_supported: bool,
}

impl BedrockProviderDiagnostics {
    const fn configured(raw_retention: RawRetentionPolicy, streaming_supported: bool) -> Self {
        Self {
            raw_retention,
            streaming_supported,
        }
    }

    /// Returns the canonical provider identity.
    #[must_use]
    pub const fn provider(&self) -> CatalogProvider {
        CatalogProvider::Bedrock
    }

    /// Returns the active raw-payload retention policy.
    #[must_use]
    pub const fn raw_retention(&self) -> RawRetentionPolicy {
        self.raw_retention
    }

    /// Reports whether exact model-revision evidence admits streaming.
    #[must_use]
    pub const fn streaming_supported(&self) -> bool {
        self.streaming_supported
    }
}

async fn build_client(region: &str, credentials: BedrockCredentialMode) -> Client {
    let configured = match credentials {
        BedrockCredentialMode::DefaultChain => {
            ClientBuilder::default().region(region).build().await
        }
        BedrockCredentialMode::NamedProfile(profile) => {
            let client = Client::with_profile_name(profile.expose_secret());
            let _ = client.get_inner().await;
            client
        }
    };

    // Rig 0.42's ClientBuilder can set a region and Client::with_profile_name can
    // select a profile, but neither API can do both or reject SDK endpoint URL
    // configuration. Rebuilding the concrete SDK config applies the validated
    // region and removes environment/profile endpoint escape hatches while
    // preserving the selected credential provider and AWS transport stack.
    let mut aws_config = configured.get_inner().await.config().to_builder();
    aws_config.set_region(Some(Region::new(region.to_owned())));
    aws_config.set_endpoint_url(None);
    Client::from(AwsBedrockRuntimeClient::from_conf(aws_config.build()))
}

#[cfg(test)]
mod tests {
    use omnius_llm_core::RawRetentionPolicy;
    use omnius_llm_provider_rig::CatalogProvider;

    use super::BedrockProviderDiagnostics;

    #[test]
    fn diagnostics_are_content_free_and_declare_streaming_readiness() {
        let diagnostics =
            BedrockProviderDiagnostics::configured(RawRetentionPolicy::Redacted, true);
        let debug = format!("{diagnostics:?}");

        assert_eq!(diagnostics.provider(), CatalogProvider::Bedrock);
        assert_eq!(diagnostics.raw_retention(), RawRetentionPolicy::Redacted);
        assert!(diagnostics.streaming_supported());
        assert!(!debug.contains("model"));
        assert!(!debug.contains("region"));
        assert!(!debug.contains("profile"));
        assert!(!debug.contains("credential"));
    }
}
