use omnius_mcp_server_core::McpRequestContext;

/// Catalog identifier for the explicitly experimental server metadata preview.
pub const SERVER_METADATA_PREVIEW_ID: &str = "server-card-preview";
/// The sole exact experimental report revision implemented by this crate.
pub const SERVER_METADATA_PREVIEW_REVISION: &str = "1";

/// Explicit server-side gate for the experimental metadata preview.
///
/// Enabling this value is necessary but insufficient: each request must also carry the exact
/// identifier and revision in its canonical [`McpRequestContext`] negotiated extension set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalPreviewConfig {
    enabled: bool,
}

impl ExperimentalPreviewConfig {
    /// Creates the default fail-closed configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Creates an explicitly enabled experimental configuration.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Returns whether server composition explicitly enabled the experimental route.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    pub(crate) fn negotiated_revision(
        self,
        request: &McpRequestContext,
    ) -> Result<&'static str, PreviewReasonCode> {
        if !self.enabled {
            return Err(PreviewReasonCode::Disabled);
        }
        let negotiated = request
            .negotiated_extensions()
            .extensions()
            .iter()
            .find(|extension| extension.id().as_str() == SERVER_METADATA_PREVIEW_ID)
            .ok_or(PreviewReasonCode::NotNegotiated)?;
        if negotiated.revision().as_str() != SERVER_METADATA_PREVIEW_REVISION {
            return Err(PreviewReasonCode::ExactRevisionRequired);
        }
        Ok(SERVER_METADATA_PREVIEW_REVISION)
    }
}

impl Default for ExperimentalPreviewConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Value-free experimental preview activation reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewReasonCode {
    /// Explicit experimental server configuration is disabled.
    Disabled,
    /// The canonical request context did not negotiate the preview identifier.
    NotNegotiated,
    /// The identifier was negotiated with a revision other than the sole implemented revision.
    ExactRevisionRequired,
}

impl PreviewReasonCode {
    /// Returns a fixed telemetry code containing no request or identity values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "preview_disabled",
            Self::NotNegotiated => "preview_not_negotiated",
            Self::ExactRevisionRequired => "preview_exact_revision_required",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{RequestContextOptions, request_context};

    #[test]
    fn disabled_config_and_exact_revision_mismatch_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let exact = request_context(&RequestContextOptions {
            requested_revision: Some(SERVER_METADATA_PREVIEW_REVISION),
            supported_revision: Some(SERVER_METADATA_PREVIEW_REVISION),
            ..RequestContextOptions::default()
        })?;
        assert_eq!(
            ExperimentalPreviewConfig::disabled().negotiated_revision(&exact),
            Err(PreviewReasonCode::Disabled)
        );

        let mismatch = request_context(&RequestContextOptions {
            requested_revision: Some("2"),
            supported_revision: Some("2"),
            ..RequestContextOptions::default()
        })?;
        assert_eq!(
            ExperimentalPreviewConfig::enabled().negotiated_revision(&mismatch),
            Err(PreviewReasonCode::ExactRevisionRequired)
        );
        Ok(())
    }

    #[test]
    fn activation_uses_only_the_canonical_exact_negotiated_extension()
    -> Result<(), Box<dyn std::error::Error>> {
        let absent = request_context(&RequestContextOptions::default())?;
        assert_eq!(
            ExperimentalPreviewConfig::enabled().negotiated_revision(&absent),
            Err(PreviewReasonCode::NotNegotiated)
        );

        let exact = request_context(&RequestContextOptions {
            requested_revision: Some(SERVER_METADATA_PREVIEW_REVISION),
            supported_revision: Some(SERVER_METADATA_PREVIEW_REVISION),
            ..RequestContextOptions::default()
        })?;
        assert_eq!(
            ExperimentalPreviewConfig::enabled().negotiated_revision(&exact),
            Ok(SERVER_METADATA_PREVIEW_REVISION)
        );
        Ok(())
    }
}
