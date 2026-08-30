//! Vertex companion adapter boundary, secrecy, and no-downgrade contracts.

use std::error::Error;

use omnius_config::SecretString;
use omnius_llm_core::{
    LlmInputPart, LlmMessage, LlmProvider, LlmRequest, LlmRequestId, MessageRole, ModelCapability,
    ModelCapabilityDeclaration, OutputMode, OutputRequest, ProviderError, ProviderErrorKind,
    RawRetentionPolicy, RequestLimits, RetryClass, Route, UnsupportedFeature,
};
use omnius_llm_provider_rig::CatalogProvider;
use omnius_llm_provider_vertex::{
    RIG_VERTEXAI_COMPATIBILITY_VERSION, VERTEX_CAPABILITY_REGISTRY_REVISION, VertexCredentialMode,
    VertexProvider, VertexProviderConfig, capability_declaration,
};

fn protected_service_account() -> SecretString {
    SecretString::from(
        serde_json::json!({
            "client_email": "credential-marker@project.iam.gserviceaccount.com",
            "private_key_id": "private-key-id-marker",
            "private_key": "private-key-secret-marker",
            "project_id": "credential-project-marker",
            "universe_domain": "attacker.invalid"
        })
        .to_string(),
    )
}

async fn provider() -> Result<VertexProvider, ProviderError> {
    VertexProvider::new(VertexProviderConfig::new(
        "project-marker".to_owned(),
        "location-marker".to_owned(),
        "model-marker".to_owned(),
        VertexCredentialMode::ServiceAccountJson(protected_service_account()),
        RawRetentionPolicy::Redacted,
    )?)
    .await
}

fn request() -> Result<LlmRequest, Box<dyn Error>> {
    LlmRequest::new(
        LlmRequestId::new("vertex-request-1".to_owned())?,
        Route::new("vertex".to_owned(), None, Vec::new(), Vec::new())?,
        vec![LlmMessage::new(
            MessageRole::User,
            vec![LlmInputPart::text("prompt-marker".to_owned())],
        )?],
        OutputRequest::new(OutputMode::Text),
        RequestLimits::new(1_000, 1, 4)?,
    )
    .map_err(Into::into)
}

#[test]
fn identifiers_are_non_empty_and_bounded() -> Result<(), Box<dyn Error>> {
    let invalid_values = [String::new(), " ".to_owned(), "x".repeat(257)];
    for invalid in invalid_values {
        let result = VertexProviderConfig::new(
            invalid,
            "global".to_owned(),
            "gemini-fixture".to_owned(),
            VertexCredentialMode::ApplicationDefault,
            RawRetentionPolicy::Discard,
        );
        let error = result.err().ok_or("invalid project was accepted")?;
        assert_eq!(error.kind(), ProviderErrorKind::Schema);
        assert_eq!(error.retry_class(), RetryClass::Never);
    }

    let location_error = VertexProviderConfig::new(
        "project".to_owned(),
        "x".repeat(257),
        "gemini-fixture".to_owned(),
        VertexCredentialMode::ApplicationDefault,
        RawRetentionPolicy::Discard,
    )
    .err()
    .ok_or("overlong location was accepted")?;
    assert_eq!(location_error.kind(), ProviderErrorKind::Schema);

    let model_error = VertexProviderConfig::new(
        "project".to_owned(),
        "global".to_owned(),
        "x".repeat(257),
        VertexCredentialMode::ApplicationDefault,
        RawRetentionPolicy::Discard,
    )
    .err()
    .ok_or("overlong model was accepted")?;
    assert_eq!(model_error.kind(), ProviderErrorKind::Schema);
    Ok(())
}

#[tokio::test]
async fn explicit_credential_parse_failure_is_typed_and_non_retryable() -> Result<(), Box<dyn Error>>
{
    let config = VertexProviderConfig::new(
        "project".to_owned(),
        "global".to_owned(),
        "gemini-fixture".to_owned(),
        VertexCredentialMode::ServiceAccountJson(SecretString::from("not-json".to_owned())),
        RawRetentionPolicy::Discard,
    )?;
    let error = VertexProvider::new(config)
        .await
        .err()
        .ok_or("malformed credential document was accepted")?;
    assert_eq!(error.kind(), ProviderErrorKind::Schema);
    assert_eq!(error.retry_class(), RetryClass::Never);
    assert_eq!(error.provider(), CatalogProvider::Vertex.as_str());
    Ok(())
}

#[tokio::test]
async fn debug_and_diagnostics_are_content_free() -> Result<(), Box<dyn Error>> {
    let credentials = VertexCredentialMode::ServiceAccountJson(protected_service_account());
    let credential_debug = format!("{credentials:?}");
    assert!(!credential_debug.contains("private-key-secret-marker"));
    assert!(!credential_debug.contains("attacker.invalid"));

    let config = VertexProviderConfig::new(
        "secret-project-marker".to_owned(),
        "secret-location-marker".to_owned(),
        "secret-model-marker".to_owned(),
        credentials,
        RawRetentionPolicy::Full,
    )?;
    let config_debug = format!("{config:?}");
    for secret in [
        "secret-project-marker",
        "secret-location-marker",
        "secret-model-marker",
        "credential-marker",
        "private-key-secret-marker",
        "attacker.invalid",
    ] {
        assert!(!config_debug.contains(secret));
    }

    let provider = VertexProvider::new(config).await?;
    let provider_debug = format!("{provider:?}");
    let diagnostics_debug = format!("{:?}", provider.diagnostics());
    for secret in [
        "secret-project-marker",
        "secret-location-marker",
        "secret-model-marker",
        "credential-marker",
        "private-key-secret-marker",
        "attacker.invalid",
    ] {
        assert!(!provider_debug.contains(secret));
        assert!(!diagnostics_debug.contains(secret));
    }
    assert_eq!(provider.diagnostics().provider(), CatalogProvider::Vertex);
    assert!(!provider.diagnostics().streaming_supported());
    Ok(())
}

#[test]
fn constructor_contract_has_no_endpoint_override() {
    type SafeConstructor = fn(
        String,
        String,
        String,
        VertexCredentialMode,
        RawRetentionPolicy,
    ) -> Result<VertexProviderConfig, ProviderError>;

    let _: SafeConstructor = VertexProviderConfig::new;
}

#[tokio::test]
async fn provider_port_is_object_safe_and_sdk_free() -> Result<(), Box<dyn Error>> {
    fn accepts_core_port(_provider: &dyn LlmProvider) {}

    let provider = provider().await?;
    accepts_core_port(&provider);
    assert_eq!(provider.diagnostics().provider(), CatalogProvider::Vertex);
    Ok(())
}

#[tokio::test]
async fn streaming_is_typed_non_retryable_and_never_downgrades() -> Result<(), Box<dyn Error>> {
    let provider = provider().await?;
    let error = LlmProvider::stream(&provider, request()?)
        .await
        .err()
        .ok_or("Vertex streaming unexpectedly opened")?;
    assert_eq!(error.kind(), ProviderErrorKind::Unsupported);
    assert_eq!(
        error.unsupported_feature(),
        Some(UnsupportedFeature::Streaming)
    );
    assert_eq!(error.retry_class(), RetryClass::Never);
    assert_eq!(error.provider(), CatalogProvider::Vertex.as_str());
    Ok(())
}

#[test]
fn revisioned_fixture_deliberately_omits_streaming() -> Result<(), Box<dyn Error>> {
    let fixture: ModelCapabilityDeclaration = serde_yaml::from_str(include_str!(
        "fixtures/vertex-capabilities-rig-0.42.0-v1.yaml"
    ))?;
    assert_eq!(RIG_VERTEXAI_COMPATIBILITY_VERSION, "0.42.0");
    assert_eq!(
        fixture.registry_revision(),
        VERTEX_CAPABILITY_REGISTRY_REVISION
    );
    assert_eq!(fixture.key().provider(), CatalogProvider::Vertex.as_str());
    assert!(fixture.supports(ModelCapability::TextInput));
    assert!(fixture.supports(ModelCapability::TextOutput));
    assert!(!fixture.supports(ModelCapability::Tools));
    assert!(!fixture.supports(ModelCapability::ImageInput));
    assert!(!fixture.supports(ModelCapability::Streaming));
    Ok(())
}

#[test]
fn capability_constructor_matches_no_streaming_fixture() -> Result<(), Box<dyn Error>> {
    let declaration = capability_declaration(
        "gemini-fixture".to_owned(),
        "gemini-fixture-001".to_owned(),
        "global".to_owned(),
        "rig-vertexai-0.42.0-source".to_owned(),
    )?;
    assert_eq!(
        declaration.key().provider(),
        CatalogProvider::Vertex.as_str()
    );
    assert_eq!(declaration.regions().len(), 1);
    assert!(!declaration.supports(ModelCapability::Tools));
    assert!(!declaration.supports(ModelCapability::ImageInput));
    assert!(!declaration.supports(ModelCapability::Streaming));
    Ok(())
}
