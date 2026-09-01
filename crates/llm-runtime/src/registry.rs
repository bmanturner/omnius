use std::{collections::BTreeMap, sync::Arc};

use omnius_llm_core::{LlmProvider, ModelCapabilityKey, RawRetentionPolicy};
use omnius_llm_provider_rig::{DirectProvider, RigProvider, RigProviderConfig};
use omnius_llm_routing::{CandidateId, RouteDefinition};
use omnius_outbound_http::OutboundHttpClients;
use thiserror::Error;

use crate::config::{DirectProviderConfig, RawRetentionConfig, RigProvidersConfig};

/// One immutable provider binding for an exact configured route candidate.
pub struct ProviderBinding {
    candidate_id: CandidateId,
    target: ModelCapabilityKey,
    provider: Arc<dyn LlmProvider>,
}

impl ProviderBinding {
    /// Creates a candidate-to-provider binding with its exact capability identity.
    #[must_use]
    pub fn new(
        candidate_id: CandidateId,
        target: ModelCapabilityKey,
        provider: Arc<dyn LlmProvider>,
    ) -> Self {
        Self {
            candidate_id,
            target,
            provider,
        }
    }
}

/// Immutable candidate-to-provider registry.
#[derive(Clone)]
pub struct ProviderRegistry {
    bindings: Arc<BTreeMap<CandidateId, BoundProvider>>,
}

#[derive(Clone)]
pub(crate) struct BoundProvider {
    pub(crate) target: ModelCapabilityKey,
    pub(crate) provider: Arc<dyn LlmProvider>,
}

impl ProviderRegistry {
    /// Builds a registry and rejects duplicate candidate identities.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderRegistryError::DuplicateCandidate`] for duplicate bindings.
    pub fn new(
        bindings: impl IntoIterator<Item = ProviderBinding>,
    ) -> Result<Self, ProviderRegistryError> {
        let mut indexed = BTreeMap::new();
        for binding in bindings {
            let bound = BoundProvider {
                target: binding.target,
                provider: binding.provider,
            };
            if indexed.insert(binding.candidate_id, bound).is_some() {
                return Err(ProviderRegistryError::DuplicateCandidate);
            }
        }
        Ok(Self {
            bindings: Arc::new(indexed),
        })
    }

    pub(crate) fn get(&self, candidate_id: &CandidateId) -> Option<&BoundProvider> {
        self.bindings.get(candidate_id)
    }

    pub(crate) fn validate_route(
        &self,
        route: &RouteDefinition,
    ) -> Result<(), ProviderRegistryError> {
        for candidate in route.candidates() {
            let binding = self
                .bindings
                .get(candidate.id())
                .ok_or(ProviderRegistryError::MissingCandidate)?;
            if binding.target != *candidate.target() {
                return Err(ProviderRegistryError::TargetMismatch);
            }
        }
        Ok(())
    }
}

/// Constructs direct Rig bindings from strict provider configuration.
///
/// Bedrock and Vertex remain owned by their separate adapters and cannot enter this constructor.
///
/// # Errors
///
/// Returns a redacted configuration or duplicate-binding failure.
pub fn build_rig_provider_registry(
    config: RigProvidersConfig,
    outbound_http: &Arc<OutboundHttpClients>,
) -> Result<ProviderRegistry, ProviderRegistryError> {
    let mut bindings = Vec::with_capacity(config.registrations.len());
    for registration in config.registrations {
        let provider = direct_provider(registration.provider);
        let provider_config = RigProviderConfig::new(
            provider,
            registration.model.clone(),
            registration.api_key,
            Arc::clone(outbound_http),
            retention(registration.raw_retention),
        )
        .map_err(|_| ProviderRegistryError::ProviderConfiguration)?;
        let provider = RigProvider::new(provider_config)
            .map_err(|_| ProviderRegistryError::ProviderConfiguration)?;
        let candidate_id = CandidateId::new(registration.candidate_id)
            .map_err(|_| ProviderRegistryError::ProviderConfiguration)?;
        let target = ModelCapabilityKey::new(
            provider.diagnostics().provider().as_str(),
            registration.model,
            registration.revision,
        )
        .map_err(|_| ProviderRegistryError::ProviderConfiguration)?;
        bindings.push(ProviderBinding::new(
            candidate_id,
            target,
            Arc::new(provider),
        ));
    }
    ProviderRegistry::new(bindings)
}

fn direct_provider(provider: DirectProviderConfig) -> DirectProvider {
    match provider {
        DirectProviderConfig::OpenAi => DirectProvider::OpenAi,
        DirectProviderConfig::Anthropic => DirectProvider::Anthropic,
        DirectProviderConfig::Gemini => DirectProvider::Gemini,
        DirectProviderConfig::OpenRouter => DirectProvider::OpenRouter,
    }
}

fn retention(policy: RawRetentionConfig) -> RawRetentionPolicy {
    match policy {
        RawRetentionConfig::Discard => RawRetentionPolicy::Discard,
        RawRetentionConfig::Redacted => RawRetentionPolicy::Redacted,
        RawRetentionConfig::Full => RawRetentionPolicy::Full,
    }
}

/// Provider registry construction failure without secret or model contents.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProviderRegistryError {
    /// A candidate identity appears more than once.
    #[error("LLM provider candidate binding is duplicated")]
    DuplicateCandidate,
    /// A route candidate has no provider binding.
    #[error("LLM route candidate has no provider binding")]
    MissingCandidate,
    /// A binding names a different provider/model/revision than the route candidate.
    #[error("LLM provider binding target does not match its route candidate")]
    TargetMismatch,
    /// Direct provider configuration was rejected.
    #[error("LLM provider configuration is invalid")]
    ProviderConfiguration,
}
