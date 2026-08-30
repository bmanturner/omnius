use std::fmt;

use omnius_config::{ExposeSecret as _, SecretString};
use omnius_llm_core::{
    ModelCapability, ModelCapabilityDeclaration, ProviderError, ProviderErrorKind,
    RawRetentionPolicy, RetryClass,
};

const MAX_MODEL_BYTES: usize = 256;
const MAX_PROFILE_BYTES: usize = 128;
const MAX_REGION_BYTES: usize = 64;
const PROVIDER_ID: &str = "bedrock";

/// AWS credential resolution mode for Bedrock.
///
/// The default chain supports AWS workload identity, web identity, container,
/// instance metadata, environment, and shared configuration providers. A named
/// profile is retained in a protected string. There is deliberately no variant
/// accepting an access key or secret key.
///
/// ```compile_fail
/// use omnius_llm_provider_bedrock::BedrockCredentialMode;
///
/// let credentials = BedrockCredentialMode::StaticKeys {
///     access_key: "access-key".to_owned(),
///     secret_key: "secret-key".to_owned(),
/// };
/// ```
pub enum BedrockCredentialMode {
    /// Resolve credentials with the AWS SDK default credential chain.
    DefaultChain,
    /// Resolve credentials and AWS configuration from the protected named profile.
    NamedProfile(SecretString),
}

impl BedrockCredentialMode {
    /// Returns whether this mode uses a named AWS profile.
    #[must_use]
    pub const fn uses_named_profile(&self) -> bool {
        matches!(self, Self::NamedProfile(_))
    }
}

impl fmt::Debug for BedrockCredentialMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultChain => formatter.write_str("DefaultChain"),
            Self::NamedProfile(_) => formatter
                .debug_tuple("NamedProfile")
                .field(&"[REDACTED]")
                .finish(),
        }
    }
}

/// Validated construction input for one AWS Bedrock completion model.
///
/// Region, model, and named-profile identifiers are non-empty, bounded, and
/// control-character free. Endpoint overrides are intentionally absent; the
/// provider always restores the AWS regional endpoint resolver after loading
/// AWS configuration.
///
/// ```compile_fail
/// use omnius_config::SecretString;
/// use omnius_llm_core::RawRetentionPolicy;
/// use omnius_llm_provider_bedrock::{BedrockCredentialMode, BedrockProviderConfig};
///
/// # fn endpoint_override_is_unavailable() -> Result<(), omnius_llm_core::ProviderError> {
/// let config = BedrockProviderConfig::new(
///     "us-east-1".to_owned(),
///     "runtime-model-id".to_owned(),
///     "runtime-model-revision".to_owned(),
///     BedrockCredentialMode::NamedProfile(SecretString::from("production".to_owned())),
///     RawRetentionPolicy::Redacted,
/// )?;
/// config.with_endpoint("https://example.invalid");
/// # Ok(())
/// # }
/// ```
pub struct BedrockProviderConfig {
    region: String,
    model_revision: String,
    model: String,
    credentials: BedrockCredentialMode,
    raw_retention: RawRetentionPolicy,
    streaming_supported: bool,
}

impl BedrockProviderConfig {
    /// Validates and owns Bedrock construction configuration.
    ///
    /// # Errors
    ///
    /// Returns a content-free, non-retryable schema error when the region,
    /// model, or named profile is invalid.
    pub fn new(
        region: String,
        model: String,
        model_revision: String,
        credentials: BedrockCredentialMode,
        raw_retention: RawRetentionPolicy,
    ) -> Result<Self, ProviderError> {
        let profile_is_valid = match &credentials {
            BedrockCredentialMode::DefaultChain => true,
            BedrockCredentialMode::NamedProfile(profile) => {
                valid_identifier(profile.expose_secret(), MAX_PROFILE_BYTES)
            }
        };
        if !valid_region(&region)
            || !valid_identifier(&model, MAX_MODEL_BYTES)
            || !valid_identifier(&model_revision, MAX_MODEL_BYTES)
            || !profile_is_valid
        {
            return Err(config_error());
        }
        Ok(Self {
            region,
            model,
            model_revision,
            credentials,
            raw_retention,
            streaming_supported: false,
        })
    }

    /// Borrows the configured AWS region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Borrows the runtime Bedrock model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Borrows the exact runtime model revision used for capability admission.
    #[must_use]
    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }

    /// Borrows the protected credential resolution mode.
    #[must_use]
    pub const fn credentials(&self) -> &BedrockCredentialMode {
        &self.credentials
    }

    /// Returns the raw provider-payload retention policy.
    #[must_use]
    pub const fn raw_retention(&self) -> RawRetentionPolicy {
        self.raw_retention
    }

    /// Applies an evidence-backed declaration for this exact model and region.
    ///
    /// Provider-native streaming remains disabled unless the exact declaration
    /// explicitly contains [`ModelCapability::Streaming`].
    ///
    /// # Errors
    ///
    /// Returns a content-free schema error when provider, model, revision, or
    /// region does not match this configuration.
    pub fn with_model_capabilities(
        mut self,
        declaration: &ModelCapabilityDeclaration,
    ) -> Result<Self, ProviderError> {
        if declaration.key().provider() != PROVIDER_ID
            || declaration.key().model() != self.model
            || declaration.key().revision() != self.model_revision
            || !declaration.regions().contains(&self.region)
        {
            return Err(config_error());
        }
        self.streaming_supported = declaration.supports(ModelCapability::Streaming);
        Ok(self)
    }

    /// Reports whether exact revision evidence admits provider-native streaming.
    #[must_use]
    pub const fn streaming_supported(&self) -> bool {
        self.streaming_supported
    }

    pub(crate) fn into_parts(self) -> BedrockProviderConfigParts {
        BedrockProviderConfigParts {
            region: self.region,
            model: self.model,
            credentials: self.credentials,
            raw_retention: self.raw_retention,
            streaming_supported: self.streaming_supported,
        }
    }
}

impl fmt::Debug for BedrockProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BedrockProviderConfig")
            .field("region", &"[REDACTED]")
            .field("model", &"[REDACTED]")
            .field("model_revision", &"[REDACTED]")
            .field("credentials", &"[REDACTED]")
            .field("raw_retention", &self.raw_retention)
            .field("streaming_supported", &self.streaming_supported)
            .finish()
    }
}

pub(crate) struct BedrockProviderConfigParts {
    pub(crate) region: String,
    pub(crate) model: String,
    pub(crate) credentials: BedrockCredentialMode,
    pub(crate) raw_retention: RawRetentionPolicy,
    pub(crate) streaming_supported: bool,
}

fn config_error() -> ProviderError {
    ProviderError::new(
        PROVIDER_ID.to_owned(),
        ProviderErrorKind::Schema,
        RetryClass::Never,
    )
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_region(region: &str) -> bool {
    valid_identifier(region, MAX_REGION_BYTES)
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && region
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && region
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use omnius_config::SecretString;
    use omnius_llm_core::{ProviderErrorKind, RawRetentionPolicy, RetryClass};

    use super::{BedrockCredentialMode, BedrockProviderConfig, MAX_MODEL_BYTES, MAX_PROFILE_BYTES};

    #[test]
    fn config_rejects_empty_and_oversized_identifiers_without_values_in_errors() {
        let cases = [
            BedrockProviderConfig::new(
                String::new(),
                "model".to_owned(),
                "model-revision".to_owned(),
                BedrockCredentialMode::DefaultChain,
                RawRetentionPolicy::Discard,
            ),
            BedrockProviderConfig::new(
                "us-east-1".to_owned(),
                "x".repeat(MAX_MODEL_BYTES + 1),
                "model-revision".to_owned(),
                BedrockCredentialMode::DefaultChain,
                RawRetentionPolicy::Discard,
            ),
            BedrockProviderConfig::new(
                "us-east-1".to_owned(),
                "model".to_owned(),
                "model-revision".to_owned(),
                BedrockCredentialMode::NamedProfile(SecretString::from(
                    "x".repeat(MAX_PROFILE_BYTES + 1),
                )),
                RawRetentionPolicy::Discard,
            ),
        ];

        for result in cases {
            let Some(error) = result.err() else {
                panic!("invalid Bedrock configuration was accepted");
            };
            assert_eq!(error.kind(), ProviderErrorKind::Schema);
            assert_eq!(error.retry_class(), RetryClass::Never);
            assert_eq!(error.provider(), "bedrock");
        }
    }

    #[test]
    fn config_and_credential_debug_redact_identifiers() -> Result<(), omnius_llm_core::ProviderError>
    {
        let profile = "sensitive-profile-name";
        let model = "sensitive-model-id";
        let region = "us-secret-1";
        let config = BedrockProviderConfig::new(
            region.to_owned(),
            model.to_owned(),
            "model-revision".to_owned(),
            BedrockCredentialMode::NamedProfile(SecretString::from(profile.to_owned())),
            RawRetentionPolicy::Redacted,
        )?;
        let config_debug = format!("{config:?}");
        let credential_debug = format!("{:?}", config.credentials());

        assert!(!config_debug.contains(profile));
        assert!(!config_debug.contains(model));
        assert!(!config_debug.contains(region));
        assert!(!credential_debug.contains(profile));
        Ok(())
    }
}
