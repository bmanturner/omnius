//! Application-owned privacy and LLM contracts.

#[cfg(test)]
use crate::ports::LlmEvaluationRepositoryPort;
#[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
use crate::ports::LlmMediaAuthorizationPort;
#[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
use crate::ports::LlmMediaScannerPort;
#[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
use crate::ports::LlmToolAuditPort;
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-http-api",
    test
))]
use crate::ports::LlmToolAuthorizationPort;
#[cfg(any(feature = "data-lifecycle", test))]
use crate::ports::PrivacyAuthorizerPort;
#[cfg(any(feature = "consent", test))]
use crate::ports::PrivacyConsentPolicyPort;
#[cfg(any(feature = "data-lifecycle", test))]
use crate::ports::PrivacyInventoryAdaptersPort;
#[cfg(any(feature = "data-lifecycle", test))]
use crate::ports::PrivacyInventoryManifestPort;
#[cfg(any(feature = "data-lifecycle", test))]
use crate::ports::PrivacyLifecycleHandlerPort;
#[cfg(any(feature = "moderation", test))]
use crate::ports::PrivacyModerationPolicyPort;

/// Application-owned privacy contract.
#[derive(Default)]
#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
pub struct PrivacyRuntime {
    #[cfg(any(feature = "data-lifecycle", test))]
    pub(crate) inventory_manifest: Option<std::sync::Arc<dyn PrivacyInventoryManifestPort>>,
    #[cfg(any(feature = "data-lifecycle", test))]
    pub(crate) inventory_adapters: Option<std::sync::Arc<dyn PrivacyInventoryAdaptersPort>>,
    #[cfg(any(feature = "data-lifecycle", test))]
    pub(crate) authorizer: Option<std::sync::Arc<dyn PrivacyAuthorizerPort>>,
    #[cfg(any(feature = "data-lifecycle", test))]
    pub(crate) lifecycle_handler: Option<std::sync::Arc<dyn PrivacyLifecycleHandlerPort>>,
    #[cfg(any(feature = "consent", test))]
    pub(crate) consent_policy: Option<std::sync::Arc<dyn PrivacyConsentPolicyPort>>,
    #[cfg(any(feature = "moderation", test))]
    pub(crate) moderation_policy: Option<std::sync::Arc<dyn PrivacyModerationPolicyPort>>,
}

#[cfg(any(
    feature = "data-lifecycle",
    feature = "consent",
    feature = "moderation",
    test
))]
impl PrivacyRuntime {
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(
        with_inventory_manifest,
        inventory_manifest,
        dyn PrivacyInventoryManifestPort
    );
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(
        with_inventory_adapters,
        inventory_adapters,
        dyn PrivacyInventoryAdaptersPort
    );
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(with_authorizer, authorizer, dyn PrivacyAuthorizerPort);
    #[cfg(any(feature = "data-lifecycle", test))]
    port_setter!(
        with_lifecycle_handler,
        lifecycle_handler,
        dyn PrivacyLifecycleHandlerPort
    );
    #[cfg(any(feature = "consent", test))]
    port_setter!(
        with_consent_policy,
        consent_policy,
        dyn PrivacyConsentPolicyPort
    );
    #[cfg(any(feature = "moderation", test))]
    port_setter!(
        with_moderation_policy,
        moderation_policy,
        dyn PrivacyModerationPolicyPort
    );
}

/// Application-owned LLM contract.
#[derive(Default)]
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
pub struct LlmRuntime {
    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-tool-runtime",
        feature = "llm-http-api",
        test
    ))]
    pub(crate) tool_authorization: Option<std::sync::Arc<dyn LlmToolAuthorizationPort>>,
    #[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
    pub(crate) tool_audit: Option<std::sync::Arc<dyn LlmToolAuditPort>>,
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    pub(crate) media_scanner: Option<std::sync::Arc<dyn LlmMediaScannerPort>>,
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    pub(crate) media_authorization: Option<std::sync::Arc<dyn LlmMediaAuthorizationPort>>,
    #[cfg(test)]
    pub(crate) evaluation_repository: Option<std::sync::Arc<dyn LlmEvaluationRepositoryPort>>,
}

#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-tool-runtime",
    feature = "llm-media",
    test
))]
impl LlmRuntime {
    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-tool-runtime",
        feature = "llm-http-api",
        test
    ))]
    port_setter!(
        with_tool_authorization,
        tool_authorization,
        dyn LlmToolAuthorizationPort
    );
    #[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
    port_setter!(with_tool_audit, tool_audit, dyn LlmToolAuditPort);
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    port_setter!(with_media_scanner, media_scanner, dyn LlmMediaScannerPort);
    #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
    port_setter!(
        with_media_authorization,
        media_authorization,
        dyn LlmMediaAuthorizationPort
    );
    #[cfg(test)]
    port_setter!(
        with_evaluation_repository,
        evaluation_repository,
        dyn LlmEvaluationRepositoryPort
    );
}
