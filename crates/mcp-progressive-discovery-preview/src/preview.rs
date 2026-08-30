use omnius_mcp_server_core::{McpExtension, McpRequestContext};

/// Exact experimental extension identifier required on every preview request.
pub const PROGRESSIVE_DISCOVERY_PREVIEW_ID: &str = "progressive-discovery-preview";
/// Exact experimental extension revision required on every preview request.
pub const PROGRESSIVE_DISCOVERY_PREVIEW_REVISION: &str = "1";

/// Explicit server-side gate for the experimental projection.
///
/// Enabling this configuration is necessary but insufficient: the canonical request context must
/// also contain the exact negotiated identifier and revision. Document metadata and other caller
/// fields are never consulted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryPreviewConfig {
    enabled: bool,
}

impl DiscoveryPreviewConfig {
    /// Creates the default-disabled experimental configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Explicitly enables the experimental configuration.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Returns the preview's deliberately narrow lifecycle and surface declaration.
    #[must_use]
    pub const fn status(self) -> DiscoveryPreviewStatus {
        DiscoveryPreviewStatus::ExperimentalNonconformantInternalProjection
    }

    pub(crate) fn evaluate(self, request: &McpRequestContext) -> DiscoveryPreviewDecision {
        if !self.enabled {
            return DiscoveryPreviewDecision::Inactive(DiscoveryPreviewReason::Disabled);
        }

        if request
            .negotiated_extensions()
            .extensions()
            .iter()
            .any(is_exact_preview)
        {
            return DiscoveryPreviewDecision::Active;
        }

        let requested_preview = request
            .metadata()
            .requested_extensions()
            .iter()
            .find(|extension| extension.id().as_str() == PROGRESSIVE_DISCOVERY_PREVIEW_ID);
        match requested_preview {
            Some(_) => DiscoveryPreviewDecision::Inactive(DiscoveryPreviewReason::ExactMismatch),
            None => DiscoveryPreviewDecision::Inactive(DiscoveryPreviewReason::NotNegotiated),
        }
    }
}

/// Explicit statement that this crate owns internal preview projections, not an MCP wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPreviewStatus {
    /// Experimental, nonconformant, internal partition/search/page projection only.
    ExperimentalNonconformantInternalProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiscoveryPreviewDecision {
    Active,
    Inactive(DiscoveryPreviewReason),
}

/// Value-free reason the exact experimental activation contract was not satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPreviewReason {
    /// The trusted server configuration is disabled.
    Disabled,
    /// The exact extension was not negotiated for this canonical request.
    NotNegotiated,
    /// The identifier or revision did not exactly match the configured preview contract.
    ExactMismatch,
}

fn is_exact_preview(extension: &McpExtension) -> bool {
    extension.id().as_str() == PROGRESSIVE_DISCOVERY_PREVIEW_ID
        && extension.revision().as_str() == PROGRESSIVE_DISCOVERY_PREVIEW_REVISION
}
