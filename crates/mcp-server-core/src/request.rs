//! Canonical request context required by every MCP protocol operation.

use std::fmt;

use omnius_agent_capability_registry::{InvocationContext, TenantMode};
use thiserror::Error;

use crate::{McpExtensionCatalog, McpNegotiatedExtensions, McpRequestMetadata};

/// Canonical identity and policy context resolved by a transport/auth boundary.
#[derive(Clone)]
pub struct McpCanonicalContext {
    invocation: InvocationContext,
    tenant_mode: TenantMode,
}

impl McpCanonicalContext {
    /// Creates canonical MCP context from an authenticated invocation context and selected scope.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when global mode carries a tenant or tenant mode lacks one.
    pub fn new(
        invocation: InvocationContext,
        tenant_mode: TenantMode,
    ) -> Result<Self, McpRequestContextError> {
        if matches!(
            (tenant_mode, invocation.tenant_id()),
            (TenantMode::Global, Some(_)) | (TenantMode::Tenant, None)
        ) {
            return Err(McpRequestContextError::TenantContextMismatch);
        }
        Ok(Self {
            invocation,
            tenant_mode,
        })
    }

    /// Borrows the canonical principal, authorization, policy, lifecycle, and budget context.
    #[must_use]
    pub const fn invocation(&self) -> &InvocationContext {
        &self.invocation
    }

    /// Returns the selected data-scope mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.tenant_mode
    }
}

impl fmt::Debug for McpCanonicalContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpCanonicalContext([redacted])")
    }
}

/// Complete protocol, identity, authorization, and extension context for one MCP request.
#[derive(Clone)]
pub struct McpRequestContext {
    metadata: McpRequestMetadata,
    canonical: McpCanonicalContext,
    negotiated_extensions: McpNegotiatedExtensions,
}

impl McpRequestContext {
    /// Creates a request context and negotiates extensions against server support.
    #[must_use]
    pub fn new(
        metadata: McpRequestMetadata,
        extension_catalog: &McpExtensionCatalog,
        canonical: McpCanonicalContext,
    ) -> Self {
        let negotiated_extensions = extension_catalog.negotiate(metadata.requested_extensions());
        Self {
            metadata,
            canonical,
            negotiated_extensions,
        }
    }

    /// Borrows validated protocol and client metadata.
    #[must_use]
    pub const fn metadata(&self) -> &McpRequestMetadata {
        &self.metadata
    }

    /// Borrows canonical identity and policy evidence.
    #[must_use]
    pub const fn canonical(&self) -> &McpCanonicalContext {
        &self.canonical
    }

    /// Borrows the explicitly activated extension set.
    #[must_use]
    pub const fn negotiated_extensions(&self) -> &McpNegotiatedExtensions {
        &self.negotiated_extensions
    }
}

impl fmt::Debug for McpRequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpRequestContext([redacted])")
    }
}

/// Redacted canonical request-context construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpRequestContextError {
    /// The selected tenant mode contradicted the canonical tenant context.
    #[error("MCP canonical request context is invalid")]
    TenantContextMismatch,
}
