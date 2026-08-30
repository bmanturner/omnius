//! Public Bedrock adapter boundary, capability, and secrecy contracts.

use std::error::Error;

use omnius_config::SecretString;
use omnius_llm_core::{
    CapabilityEvidenceSource, LlmProvider, ModelCapability, ModelCapabilityDeclaration,
    ProviderError, ProviderErrorKind, RawRetentionPolicy, RetryClass,
};
use omnius_llm_provider_bedrock::{
    BEDROCK_CAPABILITY_REGISTRY_REVISION, BedrockCredentialMode, BedrockProvider,
    BedrockProviderConfig, RIG_BEDROCK_COMPATIBILITY_VERSION, capability_declaration,
};

#[test]
fn invalid_public_config_returns_safe_typed_errors() -> Result<(), Box<dyn Error>> {
    let invalid_configs = [
        BedrockProviderConfig::new(
            "US EAST 1".to_owned(),
            "model".to_owned(),
            "model-revision".to_owned(),
            BedrockCredentialMode::DefaultChain,
            RawRetentionPolicy::Discard,
        ),
        BedrockProviderConfig::new(
            "us-east-1".to_owned(),
            "\nprivate-model".to_owned(),
            "model-revision".to_owned(),
            BedrockCredentialMode::DefaultChain,
            RawRetentionPolicy::Discard,
        ),
        BedrockProviderConfig::new(
            "us-east-1".to_owned(),
            "model".to_owned(),
            "model-revision".to_owned(),
            BedrockCredentialMode::NamedProfile(SecretString::from(String::new())),
            RawRetentionPolicy::Discard,
        ),
    ];

    for result in invalid_configs {
        let error = result.err().ok_or("invalid configuration was accepted")?;
        assert_eq!(error.provider(), "bedrock");
        assert_eq!(error.kind(), ProviderErrorKind::Schema);
        assert_eq!(error.retry_class(), RetryClass::Never);
        assert!(!format!("{error:?}").contains("private-model"));
        assert!(!error.to_string().contains("private-model"));
    }
    Ok(())
}

#[test]
fn public_config_debug_redacts_model_region_and_profile() -> Result<(), Box<dyn Error>> {
    let config = BedrockProviderConfig::new(
        "us-sensitive-1".to_owned(),
        "sensitive-model".to_owned(),
        "model-revision".to_owned(),
        BedrockCredentialMode::NamedProfile(SecretString::from("sensitive-profile".to_owned())),
        RawRetentionPolicy::Full,
    )?;
    let debug = format!("{config:?}");

    assert!(!debug.contains("us-sensitive-1"));
    assert!(!debug.contains("sensitive-model"));
    assert!(!debug.contains("sensitive-profile"));
    assert!(debug.contains("[REDACTED]"));
    Ok(())
}

#[test]
fn constructor_contract_has_no_endpoint_or_static_key_parameters() {
    type SafeConstructor = fn(
        String,
        String,
        String,
        BedrockCredentialMode,
        RawRetentionPolicy,
    ) -> Result<BedrockProviderConfig, ProviderError>;

    let constructor: SafeConstructor = BedrockProviderConfig::new;
    let _ = constructor;
}

#[test]
fn provider_implements_object_safe_canonical_port_without_sdk_types() {
    fn assert_provider<T: LlmProvider>() {}
    fn as_port(provider: &BedrockProvider) -> &dyn LlmProvider {
        provider
    }

    assert_provider::<BedrockProvider>();
    assert_eq!(
        std::mem::size_of_val(&(as_port as fn(&BedrockProvider) -> &dyn LlmProvider)),
        std::mem::size_of::<fn(&BedrockProvider) -> &dyn LlmProvider>()
    );
}

#[test]
fn revisioned_completion_streaming_fixture_is_evidence_backed() -> Result<(), Box<dyn Error>> {
    let fixture: ModelCapabilityDeclaration = serde_yaml::from_str(include_str!(
        "fixtures/bedrock-capabilities-rig-0.42.0-v1.yaml"
    ))?;

    assert_eq!(RIG_BEDROCK_COMPATIBILITY_VERSION, "0.42.0");
    assert_eq!(
        fixture.registry_revision(),
        BEDROCK_CAPABILITY_REGISTRY_REVISION
    );
    assert_eq!(fixture.key().provider(), "bedrock");
    assert!(fixture.supports(ModelCapability::TextInput));
    assert!(fixture.supports(ModelCapability::TextOutput));
    assert!(fixture.supports(ModelCapability::Streaming));
    assert!(!fixture.supports(ModelCapability::Tools));
    for evidence in fixture.evidence().values() {
        assert_eq!(
            evidence.source(),
            CapabilityEvidenceSource::ProviderDocumentation
        );
        assert_eq!(evidence.revision(), "rig-bedrock-0.42.0-source");
    }
    Ok(())
}

#[test]
fn capability_constructor_matches_revisioned_fixture() -> Result<(), Box<dyn Error>> {
    let declaration = capability_declaration(
        "bedrock-fixture".to_owned(),
        "bedrock-fixture-001".to_owned(),
        "us-east-1".to_owned(),
        "rig-bedrock-0.42.0-source".to_owned(),
    )?;

    assert_eq!(
        declaration.registry_revision(),
        BEDROCK_CAPABILITY_REGISTRY_REVISION
    );
    assert_eq!(declaration.regions().len(), 1);
    assert!(declaration.supports(ModelCapability::Streaming));
    assert!(!declaration.supports(ModelCapability::Tools));
    Ok(())
}

#[test]
fn streaming_requires_matching_exact_revision_evidence() -> Result<(), Box<dyn Error>> {
    let declaration = capability_declaration(
        "bedrock-fixture".to_owned(),
        "bedrock-fixture-001".to_owned(),
        "us-east-1".to_owned(),
        "rig-bedrock-0.42.0-source".to_owned(),
    )?;
    let config = BedrockProviderConfig::new(
        "us-east-1".to_owned(),
        "bedrock-fixture".to_owned(),
        "bedrock-fixture-001".to_owned(),
        BedrockCredentialMode::DefaultChain,
        RawRetentionPolicy::Discard,
    )?;
    assert!(!config.streaming_supported());
    let admitted = config.with_model_capabilities(&declaration)?;
    assert!(admitted.streaming_supported());

    let wrong_revision = BedrockProviderConfig::new(
        "us-east-1".to_owned(),
        "bedrock-fixture".to_owned(),
        "bedrock-fixture-002".to_owned(),
        BedrockCredentialMode::DefaultChain,
        RawRetentionPolicy::Discard,
    )?;
    assert!(
        wrong_revision
            .with_model_capabilities(&declaration)
            .is_err()
    );
    Ok(())
}
