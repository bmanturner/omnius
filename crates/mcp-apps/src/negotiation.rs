use omnius_mcp_server_core::{
    McpExtension, McpExtensionId, McpExtensionRevision, McpRequestContext,
};
use thiserror::Error;

/// Stable official MCP Apps extension identifier.
pub const APPS_EXTENSION_ID: &str = "io.modelcontextprotocol/ui";
/// Exact official MCP Apps extension revision implemented by this crate.
pub const APPS_EXTENSION_REVISION: &str = "2026-01-26";

/// Builds the exact official Apps extension unit for server catalogs and tests.
///
/// # Errors
///
/// Returns a redacted error if the compile-time official identifier or revision no longer
/// satisfies the shared MCP extension grammar.
pub fn apps_extension() -> Result<McpExtension, AppsNegotiationError> {
    let id = McpExtensionId::new(APPS_EXTENSION_ID).map_err(|_| AppsNegotiationError::Invalid)?;
    let revision = McpExtensionRevision::new(APPS_EXTENSION_REVISION)
        .map_err(|_| AppsNegotiationError::Invalid)?;
    Ok(McpExtension::new(id, revision))
}

/// Requires exact request-scoped activation of the official Apps extension revision.
///
/// An identifier match at another revision is rejected distinctly so no caller can silently
/// degrade exact extension negotiation to an identifier-only check.
///
/// # Errors
///
/// Returns [`AppsNegotiationError::RevisionMismatch`] when the official identifier was requested
/// at another revision, [`AppsNegotiationError::NotNegotiated`] when it was not activated, or
/// [`AppsNegotiationError::Invalid`] if the compile-time extension unit is invalid.
pub fn require_apps(context: &McpRequestContext) -> Result<(), AppsNegotiationError> {
    let expected = apps_extension()?;
    if context.negotiated_extensions().contains(&expected) {
        return Ok(());
    }
    if context
        .metadata()
        .requested_extensions()
        .iter()
        .any(|extension| extension.id().as_str() == APPS_EXTENSION_ID)
    {
        return Err(AppsNegotiationError::RevisionMismatch);
    }
    Err(AppsNegotiationError::NotNegotiated)
}

/// Fail-closed exact Apps extension negotiation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AppsNegotiationError {
    /// The official compile-time extension unit no longer satisfies the shared grammar.
    #[error("MCP Apps extension declaration is invalid")]
    Invalid,
    /// The request activated the official identifier at a different revision.
    #[error("MCP Apps extension revision mismatch")]
    RevisionMismatch,
    /// The request did not activate the exact official extension unit.
    #[error("MCP Apps extension was not negotiated")]
    NotNegotiated,
}
