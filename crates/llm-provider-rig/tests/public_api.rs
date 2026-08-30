//! Public provider adapter boundary and secrecy tests.

use std::{error::Error, sync::Arc};

use omnius_config::SecretString;
use omnius_llm_core::{
    GenerationConfig, LlmInputPart, LlmMessage, LlmProvider, LlmRequest, LlmRequestId, MessageRole,
    OutputMode, OutputRequest, ProviderErrorKind, RawRetentionPolicy, RequestLimits, RetryClass,
    Route, SchemaDefinition, UnsupportedFeature,
};
use omnius_llm_provider_rig::{DirectProvider, RigProvider, RigProviderConfig};
use omnius_outbound_http::{OutboundHttpClients, OutboundHttpConfig};

fn request_with_generation(
    generation: Option<GenerationConfig>,
) -> Result<LlmRequest, Box<dyn Error>> {
    let message = LlmMessage::new(
        MessageRole::User,
        vec![LlmInputPart::text("sensitive prompt".to_owned())],
    )?;
    let request = LlmRequest::new(
        LlmRequestId::new("request-1".to_owned())?,
        Route::new("direct".to_owned(), None, Vec::new(), Vec::new())?,
        vec![message],
        OutputRequest::new(OutputMode::Text),
        RequestLimits::new(1_000, 1, 4)?,
    )?;
    if let Some(generation) = generation {
        Ok(request.with_generation(generation)?)
    } else {
        Ok(request)
    }
}

fn outbound_http() -> Result<Arc<OutboundHttpClients>, Box<dyn Error>> {
    Ok(Arc::new(OutboundHttpClients::new(
        &OutboundHttpConfig::default(),
    )?))
}

fn provider(kind: DirectProvider) -> Result<RigProvider, Box<dyn Error>> {
    let config = RigProviderConfig::new(
        kind,
        "fixture-model".to_owned(),
        SecretString::from("super-secret-key".to_owned()),
        outbound_http()?,
        RawRetentionPolicy::Redacted,
    )?;
    RigProvider::new(config).map_err(Into::into)
}

#[test]
fn every_direct_provider_constructs_without_public_sdk_values() -> Result<(), Box<dyn Error>> {
    for kind in DirectProvider::ALL {
        let provider = provider(kind)?;
        assert_eq!(provider.diagnostics().provider(), kind.catalog_provider());
    }
    Ok(())
}

#[test]
fn provider_port_is_object_safe_without_sdk_types() -> Result<(), Box<dyn Error>> {
    fn accepts_trait_object(_provider: &dyn LlmProvider) {}

    let provider = provider(DirectProvider::OpenAi)?;
    accepts_trait_object(&provider);
    Ok(())
}

#[test]
fn unsupported_generation_control_fails_typed_instead_of_downgrading() -> Result<(), Box<dyn Error>>
{
    let request = request_with_generation(Some(GenerationConfig::new(
        Some(0.2),
        Some(0.9),
        Some(128),
        None,
        Vec::new(),
        None,
    )?))?;
    let error = provider(DirectProvider::OpenAi)?
        .validate_request(&request)
        .err()
        .ok_or("top_p unexpectedly accepted")?;
    assert_eq!(error.kind(), ProviderErrorKind::Unsupported);
    assert_eq!(error.unsupported_feature(), Some(UnsupportedFeature::TopP));
    assert_eq!(error.retry_class(), RetryClass::Never);
    Ok(())
}

#[test]
fn structured_output_fails_closed_until_local_schema_validation_exists()
-> Result<(), Box<dyn Error>> {
    let request = LlmRequest::new(
        LlmRequestId::new("request-structured".to_owned())?,
        Route::new("direct".to_owned(), None, Vec::new(), Vec::new())?,
        vec![LlmMessage::new(
            MessageRole::User,
            vec![LlmInputPart::text("return json".to_owned())],
        )?],
        OutputRequest::new(OutputMode::Structured).with_schema(
            Some("result-schema".to_owned()),
            Some(SchemaDefinition::Boolean(true)),
            Some(true),
        )?,
        RequestLimits::new(1_000, 1, 4)?,
    )?;
    let error = provider(DirectProvider::Gemini)?
        .validate_request(&request)
        .err()
        .ok_or("structured request unexpectedly accepted")?;
    assert_eq!(
        error.unsupported_feature(),
        Some(UnsupportedFeature::StructuredOutputRequiresValidation)
    );
    Ok(())
}

#[test]
fn debug_output_excludes_keys_prompts_and_provider_values() -> Result<(), Box<dyn Error>> {
    let config = RigProviderConfig::new(
        DirectProvider::Anthropic,
        "secret-model-alias".to_owned(),
        SecretString::from("super-secret-key".to_owned()),
        outbound_http()?,
        RawRetentionPolicy::Full,
    )?;
    let config_debug = format!("{config:?}");
    assert!(!config_debug.contains("super-secret-key"));
    assert!(!config_debug.contains("secret-model-alias"));
    let provider = RigProvider::new(config)?;
    let provider_debug = format!("{provider:?}");
    assert!(!provider_debug.contains("super-secret-key"));
    assert!(!provider_debug.contains("secret-model-alias"));

    let request = request_with_generation(Some(GenerationConfig::new(
        None,
        Some(0.5),
        None,
        None,
        Vec::new(),
        None,
    )?))?;
    let error = provider
        .validate_request(&request)
        .err()
        .ok_or("unsupported request unexpectedly accepted")?;
    let error_debug = format!("{error:?}");
    let error_display = error.to_string();
    assert!(!error_debug.contains("sensitive prompt"));
    assert!(!error_display.contains("sensitive prompt"));
    Ok(())
}
