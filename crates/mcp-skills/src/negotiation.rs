use omnius_mcp_server_core::{
    McpExtension, McpExtensionError, McpExtensionId, McpExtensionRevision, McpRequestContext,
};
use thiserror::Error;

/// Experimental MCP Skills extension identifier.
pub const SKILLS_EXTENSION_ID: &str = "io.modelcontextprotocol/skills";
/// The only experimental Skills extension revision implemented by this crate.
pub const SKILLS_EXTENSION_REVISION: &str = "2026-08-22";

/// Default-off server policy for the experimental Skills extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillsExtensionPolicy {
    enabled: bool,
    extension: McpExtension,
}

impl SkillsExtensionPolicy {
    /// Builds the default-off policy while validating the crate's pinned extension constants.
    ///
    /// # Errors
    ///
    /// Returns a fixed error if the compiled identifier or revision is invalid.
    pub fn disabled() -> Result<Self, NegotiationError> {
        Ok(Self {
            enabled: false,
            extension: skills_extension()?,
        })
    }

    /// Builds an explicitly enabled experimental policy.
    ///
    /// This constructor is the opt-in boundary. Skills must never be inserted into a baseline or
    /// production-stable extension catalog implicitly.
    ///
    /// # Errors
    ///
    /// Returns a fixed error if the compiled identifier or revision is invalid.
    pub fn enabled() -> Result<Self, NegotiationError> {
        Ok(Self {
            enabled: true,
            extension: skills_extension()?,
        })
    }

    /// Borrows the exact unit that an opt-in server may add to its extension catalog.
    #[must_use]
    pub const fn extension(&self) -> &McpExtension {
        &self.extension
    }

    /// Requires explicit server enablement and exact request-scoped identifier/revision negotiation.
    ///
    /// # Errors
    ///
    /// Fails closed when Skills is default-off, absent, or requested at another revision.
    pub fn require_skills(&self, request: &McpRequestContext) -> Result<(), NegotiationError> {
        if !self.enabled {
            return Err(NegotiationError::Disabled);
        }
        if request.negotiated_extensions().contains(&self.extension) {
            return Ok(());
        }
        if request
            .metadata()
            .requested_extensions()
            .iter()
            .any(|extension| extension.id().as_str() == SKILLS_EXTENSION_ID)
        {
            return Err(NegotiationError::RevisionMismatch);
        }
        Err(NegotiationError::NotNegotiated)
    }
}

/// Returns the validated exact experimental Skills extension unit.
///
/// # Errors
///
/// Returns a fixed error if the compiled identifier or revision is invalid.
pub fn skills_extension() -> Result<McpExtension, NegotiationError> {
    let id = McpExtensionId::new(SKILLS_EXTENSION_ID).map_err(NegotiationError::from)?;
    let revision =
        McpExtensionRevision::new(SKILLS_EXTENSION_REVISION).map_err(NegotiationError::from)?;
    Ok(McpExtension::new(id, revision))
}

/// Fixed, value-free Skills negotiation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NegotiationError {
    /// The compiled Skills extension declaration is invalid.
    #[error("MCP Skills extension declaration is invalid")]
    InvalidDeclaration,
    /// Experimental Skills support was not explicitly enabled by the server profile.
    #[error("MCP Skills extension is disabled")]
    Disabled,
    /// The client requested the Skills identifier at a different exact revision.
    #[error("MCP Skills extension revision does not match")]
    RevisionMismatch,
    /// The exact Skills identifier and revision were not negotiated for this request.
    #[error("MCP Skills extension was not negotiated")]
    NotNegotiated,
}

impl From<McpExtensionError> for NegotiationError {
    fn from(_: McpExtensionError) -> Self {
        Self::InvalidDeclaration
    }
}
