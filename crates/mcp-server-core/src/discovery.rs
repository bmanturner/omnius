//! Authorization-filtered discovery views over the shared capability registry.

use std::{fmt, sync::Arc};

use omnius_agent_capability_registry::CapabilityDocument;
use omnius_authz_basic::Decision;

use crate::{McpKernel, McpPrimitive, McpRequestContext};

/// Per-capability authorization boundary used for discovery and list projections.
pub trait McpExposureAuthorizer: Send + Sync {
    /// Returns whether one canonical principal may discover a declared MCP projection.
    ///
    /// Implementations receive the complete canonical request context and declaration. They must
    /// fail closed on evaluator or dependency failure.
    fn is_authorized(
        &self,
        request: &McpRequestContext,
        document: &CapabilityDocument,
        primitive: McpPrimitive,
    ) -> bool;
}

/// Stateless authorization-filtered view builder over the shared registry.
#[derive(Clone)]
pub struct McpExposureFilter {
    kernel: McpKernel,
    authorizer: Arc<dyn McpExposureAuthorizer>,
}

impl McpExposureFilter {
    /// Creates a filter with an explicit per-capability authorizer.
    #[must_use]
    pub fn new(kernel: McpKernel, authorizer: Arc<dyn McpExposureAuthorizer>) -> Self {
        Self { kernel, authorizer }
    }

    /// Produces a deterministic borrowed view containing only discoverable declarations.
    ///
    /// A declaration must be compiled, currently available, explicitly expose the requested MCP
    /// primitive, support the selected tenant mode, carry an allowed canonical request decision,
    /// and pass the supplied per-capability authorizer.
    #[must_use]
    pub fn authorized<'filter>(
        &'filter self,
        request: &McpRequestContext,
        primitive: McpPrimitive,
    ) -> McpAuthorizedExposure<'filter> {
        if request.canonical().invocation().authorization() != Decision::Allow {
            return McpAuthorizedExposure::empty();
        }

        let documents = self
            .kernel
            .availability_snapshot()
            .capabilities()
            .iter()
            .filter(|availability| availability.compiled() && availability.runtime().is_available())
            .filter_map(|availability| self.kernel.document(availability.capability()))
            .filter(|document| document.exposures.contains(&primitive.exposure()))
            .filter(|document| {
                document
                    .tenant_modes
                    .contains(&request.canonical().tenant_mode())
            })
            .filter(|document| self.authorizer.is_authorized(request, document, primitive))
            .collect();
        McpAuthorizedExposure { documents }
    }
}

impl fmt::Debug for McpExposureFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpExposureFilter([shared registry, redacted authorizer])")
    }
}

/// A deterministic borrowed set of declarations authorized for one request and primitive.
pub struct McpAuthorizedExposure<'registry> {
    documents: Vec<&'registry CapabilityDocument>,
}

impl<'registry> McpAuthorizedExposure<'registry> {
    fn empty() -> Self {
        Self {
            documents: Vec::new(),
        }
    }

    /// Borrows authorized declarations in canonical capability-key order.
    #[must_use]
    pub fn documents(&self) -> &[&'registry CapabilityDocument] {
        &self.documents
    }
}

impl fmt::Debug for McpAuthorizedExposure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAuthorizedExposure")
            .field("count", &self.documents.len())
            .finish()
    }
}
