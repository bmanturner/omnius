use std::fmt;

/// A direct API implemented by this Rig adapter crate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DirectProvider {
    /// `OpenAI` Responses API.
    OpenAi,
    /// Anthropic Messages API.
    Anthropic,
    /// Direct Google Gemini API.
    Gemini,
    /// `OpenRouter`'s `OpenAI`-compatible aggregation API.
    OpenRouter,
}

impl DirectProvider {
    /// Every direct provider accepted by [`crate::RigProviderConfig`].
    pub const ALL: [Self; 4] = [
        Self::OpenAi,
        Self::Anthropic,
        Self::Gemini,
        Self::OpenRouter,
    ];

    /// Returns the machine-catalog provider identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::OpenRouter => "openrouter",
        }
    }

    /// Returns the corresponding six-entry catalog identity.
    #[must_use]
    pub const fn catalog_provider(self) -> CatalogProvider {
        match self {
            Self::OpenAi => CatalogProvider::OpenAi,
            Self::Anthropic => CatalogProvider::Anthropic,
            Self::Gemini => CatalogProvider::Gemini,
            Self::OpenRouter => CatalogProvider::OpenRouter,
        }
    }
}

impl fmt::Display for DirectProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One provider identity declared by the machine provider catalog.
///
/// Bedrock and Vertex are represented for catalog verification, but cannot be
/// converted into a [`DirectProvider`]. Their companion adapter modules own
/// construction and execution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CatalogProvider {
    /// `OpenAI`, owned by `llm-provider-rig`.
    OpenAi,
    /// Anthropic, owned by `llm-provider-rig`.
    Anthropic,
    /// Gemini, owned by `llm-provider-rig`.
    Gemini,
    /// `OpenRouter`, owned by `llm-provider-rig`.
    OpenRouter,
    /// AWS Bedrock, reserved for `llm-provider-bedrock`.
    Bedrock,
    /// Google Vertex AI, reserved for `llm-provider-vertex`.
    Vertex,
}

impl CatalogProvider {
    /// All configured provider identities, in catalog order.
    pub const ALL: [Self; 6] = [
        Self::OpenAi,
        Self::Anthropic,
        Self::Gemini,
        Self::OpenRouter,
        Self::Bedrock,
        Self::Vertex,
    ];

    /// Returns the stable machine-catalog provider identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::OpenRouter => "openrouter",
            Self::Bedrock => "bedrock",
            Self::Vertex => "vertex",
        }
    }

    pub(crate) const fn rig_descriptor(self) -> &'static str {
        match self {
            Self::Gemini => "gcp.gemini",
            Self::Bedrock => "aws_bedrock",
            Self::Vertex => "vertexai",
            Self::OpenAi | Self::Anthropic | Self::OpenRouter => self.as_str(),
        }
    }

    /// Returns the adapter module that owns this provider.
    #[must_use]
    pub const fn adapter_module(self) -> &'static str {
        match self {
            Self::OpenAi | Self::Anthropic | Self::Gemini | Self::OpenRouter => "llm-provider-rig",
            Self::Bedrock => "llm-provider-bedrock",
            Self::Vertex => "llm-provider-vertex",
        }
    }

    /// Returns a direct provider only when this crate owns construction.
    #[must_use]
    pub const fn direct(self) -> Option<DirectProvider> {
        match self {
            Self::OpenAi => Some(DirectProvider::OpenAi),
            Self::Anthropic => Some(DirectProvider::Anthropic),
            Self::Gemini => Some(DirectProvider::Gemini),
            Self::OpenRouter => Some(DirectProvider::OpenRouter),
            Self::Bedrock | Self::Vertex => None,
        }
    }
}
