use std::fmt;

use omnius_config::{ExposeSecret, SecretString};
use omnius_llm_core::{ProviderError, ProviderErrorKind, RawRetentionPolicy, RetryClass};
use omnius_llm_provider_rig::CatalogProvider;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_SERVICE_ACCOUNT_JSON_BYTES: usize = 64 * 1024;

/// Credential source used to authenticate a Vertex AI client.
pub enum VertexCredentialMode {
    /// Google Application Default Credentials, including workload identity federation.
    ApplicationDefault,
    /// A protected Google service-account key document.
    ///
    /// Workload identity is preferred. This variant exists for deployments that
    /// cannot supply ADC without a long-lived key.
    ServiceAccountJson(SecretString),
}

impl fmt::Debug for VertexCredentialMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationDefault => formatter.write_str("ApplicationDefault"),
            Self::ServiceAccountJson(_) => formatter
                .debug_tuple("ServiceAccountJson")
                .field(&"[REDACTED]")
                .finish(),
        }
    }
}

/// Validated construction input for one Vertex AI completion model.
pub struct VertexProviderConfig {
    project: String,
    location: String,
    model: String,
    credentials: VertexCredentialMode,
    raw_retention: RawRetentionPolicy,
}

impl VertexProviderConfig {
    /// Validates and owns the Vertex AI project, location, model, and credentials.
    ///
    /// The adapter intentionally has no endpoint parameter. Rig and the Google
    /// SDK retain ownership of the fixed Vertex AI service endpoint.
    ///
    /// # Errors
    ///
    /// Returns a redacted, non-retryable schema error when an identifier is
    /// empty or longer than 256 bytes, or when an explicit credential document
    /// is empty or larger than 64 KiB.
    pub fn new(
        project: String,
        location: String,
        model: String,
        credentials: VertexCredentialMode,
        raw_retention: RawRetentionPolicy,
    ) -> Result<Self, ProviderError> {
        validate_identifier(&project)?;
        validate_identifier(&location)?;
        validate_identifier(&model)?;
        if let VertexCredentialMode::ServiceAccountJson(secret) = &credentials {
            let secret = secret.expose_secret();
            if secret.trim().is_empty() || secret.len() > MAX_SERVICE_ACCOUNT_JSON_BYTES {
                return Err(config_error());
            }
        }
        Ok(Self {
            project,
            location,
            model,
            credentials,
            raw_retention,
        })
    }

    /// Borrows the configured Google Cloud project identifier.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Borrows the configured Google Cloud location identifier.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Borrows the configured runtime model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Borrows the configured protected credential mode.
    #[must_use]
    pub const fn credentials(&self) -> &VertexCredentialMode {
        &self.credentials
    }

    /// Returns the raw provider-payload retention policy.
    #[must_use]
    pub const fn raw_retention(&self) -> RawRetentionPolicy {
        self.raw_retention
    }

    pub(crate) fn into_parts(self) -> VertexProviderConfigParts {
        VertexProviderConfigParts {
            project: self.project,
            location: self.location,
            model: self.model,
            credentials: self.credentials,
            raw_retention: self.raw_retention,
        }
    }
}

impl fmt::Debug for VertexProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VertexProviderConfig")
            .field("project", &"[REDACTED]")
            .field("location", &"[REDACTED]")
            .field("model", &"[REDACTED]")
            .field("credentials", &"[REDACTED]")
            .field("raw_retention", &self.raw_retention)
            .finish()
    }
}

pub(crate) struct VertexProviderConfigParts {
    pub(crate) project: String,
    pub(crate) location: String,
    pub(crate) model: String,
    pub(crate) credentials: VertexCredentialMode,
    pub(crate) raw_retention: RawRetentionPolicy,
}

pub(crate) fn config_error() -> ProviderError {
    ProviderError::new(
        CatalogProvider::Vertex.as_str().to_owned(),
        ProviderErrorKind::Schema,
        RetryClass::Never,
    )
}

fn validate_identifier(value: &str) -> Result<(), ProviderError> {
    if value.trim().is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        Err(config_error())
    } else {
        Ok(())
    }
}
