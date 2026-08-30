use std::{fmt, future::Future, pin::Pin, sync::Arc};

use omnius_agent_capability_registry::{
    AvailabilitySnapshot, CapabilityDocument, CapabilityInvocation, CapabilityKey,
    CapabilityRegistry, Exposure, HandlerErrorCode, InvocationError, InvocationResult,
};

/// The only MCP protocol revision implemented by this kernel.
pub const MCP_PROTOCOL_REVISION: &str = "2026-07-28";

/// A deny-by-default MCP projection kind.
///
/// This type cannot represent HTTP, jobs, browser calls, or direct LLM-tool
/// projections. Each value maps to exactly one declaration in the shared registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum McpPrimitive {
    /// An MCP tool invocation.
    Tool,
    /// An MCP resource invocation.
    Resource,
    /// An MCP prompt invocation.
    Prompt,
}

impl McpPrimitive {
    const fn exposure(self) -> Exposure {
        match self {
            Self::Tool => Exposure::McpTool,
            Self::Resource => Exposure::McpResource,
            Self::Prompt => Exposure::McpPrompt,
        }
    }
}

/// Stable, value-free failure categories at the MCP application boundary.
///
/// Authorization failures and missing capabilities deliberately share
/// [`Self::Rejected`] so callers cannot infer registry or policy state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpDispatchErrorCode {
    /// Canonical invocation evidence did not satisfy a request guardrail.
    InvalidRequest,
    /// The request was rejected without revealing registry or authorization state.
    Rejected,
    /// Execution could not complete within current availability or lifecycle bounds.
    Unavailable,
    /// Execution failed without a caller-actionable distinction.
    Internal,
}

/// A redacted MCP capability-dispatch failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct McpDispatchError {
    code: McpDispatchErrorCode,
}

impl McpDispatchError {
    /// Returns the fixed failure category safe for a protocol projection to map.
    #[must_use]
    pub const fn code(self) -> McpDispatchErrorCode {
        self.code
    }

    const fn from_invocation(error: InvocationError) -> Self {
        let code = match error {
            InvocationError::UnknownCapability
            | InvocationError::ExposureNotDeclared
            | InvocationError::Denied => McpDispatchErrorCode::Rejected,
            InvocationError::TenantModeMismatch
            | InvocationError::ConfirmationRequired
            | InvocationError::IdempotencyMismatch
            | InvocationError::InputBudgetExceeded => McpDispatchErrorCode::InvalidRequest,
            InvocationError::Unavailable
            | InvocationError::DeadlineExceeded
            | InvocationError::Cancelled => McpDispatchErrorCode::Unavailable,
            InvocationError::OutputBudgetExceeded => McpDispatchErrorCode::Internal,
            InvocationError::HandlerFailed(code) => match code {
                HandlerErrorCode::InvalidInput => McpDispatchErrorCode::InvalidRequest,
                HandlerErrorCode::Conflict | HandlerErrorCode::Rejected => {
                    McpDispatchErrorCode::Rejected
                }
                HandlerErrorCode::DependencyUnavailable => McpDispatchErrorCode::Unavailable,
                HandlerErrorCode::Internal => McpDispatchErrorCode::Internal,
            },
        };
        Self { code }
    }
}

impl fmt::Debug for McpDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpDispatchError([redacted])")
    }
}

impl fmt::Display for McpDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP capability dispatch failed")
    }
}

impl std::error::Error for McpDispatchError {}

/// The boxed future returned by the object-safe [`McpDispatch`] boundary.
pub type McpDispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<InvocationResult, McpDispatchError>> + Send + 'a>>;

/// One fully self-contained MCP capability dispatch.
///
/// Protocol metadata remains explicit at the SDK-free boundary rather than being recovered from
/// connection or session state.
pub struct McpDispatchRequest {
    metadata: crate::McpRequestMetadata,
    primitive: McpPrimitive,
    invocation: CapabilityInvocation,
}

impl McpDispatchRequest {
    /// Creates a request whose metadata and canonical invocation context are both request-scoped.
    #[must_use]
    pub const fn new(
        metadata: crate::McpRequestMetadata,
        primitive: McpPrimitive,
        invocation: CapabilityInvocation,
    ) -> Self {
        Self {
            metadata,
            primitive,
            invocation,
        }
    }

    /// Borrows the validated protocol metadata.
    #[must_use]
    pub const fn metadata(&self) -> &crate::McpRequestMetadata {
        &self.metadata
    }

    /// Returns the requested MCP projection.
    #[must_use]
    pub const fn primitive(&self) -> McpPrimitive {
        self.primitive
    }

    /// Borrows the canonical capability invocation.
    #[must_use]
    pub const fn invocation(&self) -> &CapabilityInvocation {
        &self.invocation
    }
}

impl fmt::Debug for McpDispatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpDispatchRequest([redacted])")
    }
}

/// Object-safe, SDK-free MCP dispatch boundary for composition and transports.
///
/// Every call owns freshly validated protocol metadata and a freshly constructed
/// [`CapabilityInvocation`]. Implementations may not accept or retain RMCP request state at this
/// boundary.
pub trait McpDispatch: Send + Sync {
    /// Invokes one fully self-contained MCP request through the canonical registry.
    fn dispatch(&self, request: McpDispatchRequest) -> McpDispatchFuture<'_>;
}

#[derive(Clone)]
struct RegistryProjection {
    registry: Arc<CapabilityRegistry>,
}

impl RegistryProjection {
    fn availability_snapshot(&self) -> AvailabilitySnapshot {
        self.registry.availability_snapshot()
    }

    fn document(&self, capability: &CapabilityKey) -> Option<&CapabilityDocument> {
        self.registry.document(capability)
    }

    async fn invoke(
        &self,
        primitive: McpPrimitive,
        invocation: CapabilityInvocation,
    ) -> Result<InvocationResult, McpDispatchError> {
        self.registry
            .invoke(primitive.exposure(), invocation)
            .await
            .map_err(McpDispatchError::from_invocation)
    }
}

/// Stateless MCP kernel backed by one shared immutable capability registry.
///
/// The kernel retains no client, initialization, transport, or session state.
/// Clones share only the immutable registry.
#[derive(Clone)]
pub struct McpKernel {
    projection: RegistryProjection,
}

impl McpKernel {
    /// Creates a kernel retaining the process-wide canonical capability registry.
    #[must_use]
    pub fn new(registry: Arc<CapabilityRegistry>) -> Self {
        Self {
            projection: RegistryProjection { registry },
        }
    }

    /// Returns the only protocol revision implemented by this kernel.
    #[must_use]
    pub const fn protocol_revision(&self) -> &'static str {
        MCP_PROTOCOL_REVISION
    }

    /// Returns a deterministic snapshot sourced directly from the shared registry.
    #[must_use]
    pub fn availability_snapshot(&self) -> AvailabilitySnapshot {
        self.projection.availability_snapshot()
    }

    /// Borrows canonical metadata directly from the shared registry.
    #[must_use]
    pub fn document(&self, capability: &CapabilityKey) -> Option<&CapabilityDocument> {
        self.projection.document(capability)
    }

    /// Invokes one declared MCP projection exclusively through the shared registry.
    ///
    /// The supplied invocation must already contain the canonical
    /// `InvocationContext` constructed for this request. The kernel retains none of
    /// that context after completion.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`McpDispatchError`] category without registry, policy,
    /// identity, prompt, input, output, or provider details.
    pub async fn invoke(
        &self,
        request: McpDispatchRequest,
    ) -> Result<InvocationResult, McpDispatchError> {
        let McpDispatchRequest {
            metadata,
            primitive,
            invocation,
        } = request;
        debug_assert_eq!(metadata.protocol_revision(), MCP_PROTOCOL_REVISION);
        self.projection.invoke(primitive, invocation).await
    }
}

impl McpDispatch for McpKernel {
    fn dispatch(&self, request: McpDispatchRequest) -> McpDispatchFuture<'_> {
        Box::pin(self.invoke(request))
    }
}

impl fmt::Debug for McpKernel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpKernel([shared capability registry])")
    }
}
