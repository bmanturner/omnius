use std::{collections::BTreeSet, fmt, sync::Arc};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    CapabilityInvocation, ConfirmationEvidence, IdempotencyKey, InvocationContext, TenantMode,
};
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpDispatchErrorCode, McpDispatchRequest, McpKernel, McpPrimitive,
    McpRequestContext,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CanonicalToolResult, CatalogCacheControl, CatalogMetadataError, CatalogRevision, ToolCatalog,
    ToolCatalogError, ToolDeclaration, ToolFailure, ToolFailureCode, ToolList, ToolName,
    ToolRepresentation,
};

/// Discovery or call operation evaluated by the narrow authorization port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolAuthorizationOperation {
    /// Authorization to enumerate one catalog declaration.
    Discover,
    /// Authorization to route a call by name or execute it with validated input.
    Call,
}

/// A borrowed, transport-neutral tool authorization request.
///
/// The request exposes no handler or dispatch facility. Call input, when present, has already
/// passed the declaration's compiled input schema and is available only for resolved-resource
/// policy decisions.
pub struct ToolAuthorizationRequest<'a> {
    operation: ToolAuthorizationOperation,
    request_context: &'a McpRequestContext,
    declaration: &'a ToolDeclaration,
    input: Option<&'a Value>,
}

impl ToolAuthorizationRequest<'_> {
    /// Returns the requested authorization operation.
    #[must_use]
    pub const fn operation(&self) -> ToolAuthorizationOperation {
        self.operation
    }

    /// Returns the complete canonical request context.
    #[must_use]
    pub const fn request_context(&self) -> &McpRequestContext {
        self.request_context
    }

    /// Returns the canonical invocation context.
    #[must_use]
    pub const fn context(&self) -> &InvocationContext {
        self.request_context.canonical().invocation()
    }

    /// Returns the explicit catalog declaration.
    #[must_use]
    pub const fn declaration(&self) -> &ToolDeclaration {
        self.declaration
    }

    /// Returns the selected canonical tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.request_context.canonical().tenant_mode()
    }

    /// Returns already schema-validated call input, if any.
    #[must_use]
    pub const fn input(&self) -> Option<&Value> {
        self.input
    }
}

impl fmt::Debug for ToolAuthorizationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolAuthorizationRequest([redacted])")
    }
}

/// Fail-closed decision returned by the narrow tool authorization port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolAuthorizationDecision {
    /// The specific discovery or call operation is allowed.
    Allow,
    /// The operation is omitted or rejected without revealing policy state.
    Deny,
}

/// Narrow asynchronous authorization port for discovery and calls.
///
/// Implementations cannot execute capabilities. The only execution path remains
/// [`McpKernel::invoke`]. Dependency failures must be represented as [`ToolAuthorizationDecision::Deny`].
#[async_trait]
pub trait ToolAuthorizer: Send + Sync {
    /// Authorizes exactly one discovery entry or validated call.
    async fn authorize(&self, request: ToolAuthorizationRequest<'_>) -> ToolAuthorizationDecision;
}

/// Fixed protocol routing or pre-dispatch validation rejection.
///
/// Unknown names, extension ineligibility, and authorization denial deliberately share
/// [`Self::Rejected`] so callers cannot infer catalog or policy state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolProtocolError {
    /// A routed request failed fixed pre-dispatch validation.
    #[error("tool protocol request is invalid")]
    InvalidRequest,
    /// Routing or authorization was rejected without revealing why.
    #[error("tool protocol request was rejected")]
    Rejected,
}

/// One self-contained canonical tool call.
pub struct ToolCallRequest {
    request_context: McpRequestContext,
    name: ToolName,
    input: Value,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
}

impl ToolCallRequest {
    /// Creates a self-contained canonical tool call.
    #[must_use]
    pub fn new(
        request_context: McpRequestContext,
        name: ToolName,
        input: Value,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            request_context,
            name,
            input,
            confirmation,
            idempotency_key,
        }
    }

    /// Returns the complete canonical request context.
    #[must_use]
    pub const fn request_context(&self) -> &McpRequestContext {
        &self.request_context
    }

    /// Returns the stable public tool name.
    #[must_use]
    pub const fn name(&self) -> &ToolName {
        &self.name
    }

    /// Borrows untrusted input before projection validation.
    #[must_use]
    pub const fn input(&self) -> &Value {
        &self.input
    }

    /// Returns canonical confirmation evidence.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationEvidence {
        self.confirmation
    }

    /// Returns the optional canonical idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

impl fmt::Debug for ToolCallRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolCallRequest([redacted])")
    }
}

/// Immutable MCP tool projection over one shared registry kernel.
///
/// This type owns no session or transport behavior and accepts no executable handler registry.
pub struct ToolProjection {
    kernel: Arc<McpKernel>,
    catalog: ToolCatalog,
    authorizer: Arc<dyn ToolAuthorizer>,
}

impl ToolProjection {
    /// Compiles an immutable catalog tied to MCP-tool exposures in the supplied kernel.
    ///
    /// # Errors
    ///
    /// Returns [`ToolCatalogError`] for duplicates, missing registry capabilities, undeclared
    /// MCP-tool exposures, or invalid deprecation metadata.
    pub fn new(
        kernel: Arc<McpKernel>,
        catalog_revision: CatalogRevision,
        cache_control: CatalogCacheControl,
        declarations: impl IntoIterator<Item = ToolDeclaration>,
        authorizer: Arc<dyn ToolAuthorizer>,
    ) -> Result<Self, ToolCatalogError> {
        let catalog = ToolCatalog::compile(
            catalog_revision,
            cache_control,
            declarations,
            kernel.as_ref(),
        )?;
        Ok(Self {
            kernel,
            catalog,
            authorizer,
        })
    }

    /// Returns the only supported current MCP protocol revision.
    #[must_use]
    pub const fn protocol_revision(&self) -> &'static str {
        MCP_PROTOCOL_REVISION
    }

    /// Returns the immutable catalog.
    #[must_use]
    pub const fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    /// Returns a deterministic authorized, extension-eligible, currently available tool list.
    ///
    /// Unauthorized, tenant-ineligible, and extension-ineligible declarations are omitted entirely.
    /// `_meta` contains the exact Omnius catalog keys, prevalidated cache policy, and an `ETag`
    /// derived from the immutable catalog revision plus the exact ordered visible list.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogMetadataError`] only if deterministic list serialization fails.
    pub async fn list_tools(
        &self,
        request: &McpRequestContext,
    ) -> Result<ToolList, CatalogMetadataError> {
        let context = request.canonical().invocation();
        let tenant_mode = request.canonical().tenant_mode();
        if context.authorization() != Decision::Allow {
            return ToolList::new(
                Vec::new(),
                self.catalog.revision(),
                self.catalog.cache_control(),
            );
        }
        let available = self
            .kernel
            .availability_snapshot()
            .capabilities()
            .iter()
            .filter(|status| status.compiled() && status.runtime().is_available())
            .map(|status| status.capability().clone())
            .collect::<BTreeSet<_>>();
        let mut visible = Vec::new();
        for entry in self.catalog.entries().values() {
            let Some(document) = self.kernel.document(entry.declaration.capability()) else {
                continue;
            };
            if !available.contains(entry.declaration.capability())
                || !document.tenant_modes.contains(&tenant_mode)
                || !entry
                    .declaration
                    .required_extensions()
                    .iter()
                    .all(|extension| request.negotiated_extensions().contains(extension))
            {
                continue;
            }
            let request = ToolAuthorizationRequest {
                operation: ToolAuthorizationOperation::Discover,
                request_context: request,
                declaration: &entry.declaration,
                input: None,
            };
            if self.authorizer.authorize(request).await == ToolAuthorizationDecision::Allow {
                visible.push(entry.descriptor.clone());
            }
        }
        ToolList::new(
            visible,
            self.catalog.revision(),
            self.catalog.cache_control(),
        )
    }

    /// Authorizes routing, validates, authorizes resolved input, invokes, and validates output.
    ///
    /// The canonical context decision is checked first. Name-level authorization then runs before
    /// schema validation so unauthorized callers cannot use validation behavior as a schema oracle.
    /// Resolved-input authorization runs again with already validated input before construction of
    /// the canonical registry invocation. Successful execution always traverses
    /// `McpKernel::invoke(McpDispatchRequest)`; registry consent, side-effect, confirmation,
    /// idempotency, tenant, budget, deadline, cancellation, and availability policy remains
    /// authoritative. Output is validated after registry execution and represented as one arbitrary
    /// structured value.
    ///
    /// # Errors
    ///
    /// Returns [`ToolProtocolError::Rejected`] for a canonical deny, unknown, extension-ineligible,
    /// or authorization-denied request. Returns [`ToolProtocolError::InvalidRequest`] when
    /// authorized input fails the declared schema. Failures after kernel invocation are complete
    /// tool-level error results.
    pub async fn call(
        &self,
        request: ToolCallRequest,
    ) -> Result<CanonicalToolResult, ToolProtocolError> {
        let ToolCallRequest {
            request_context,
            name,
            input,
            confirmation,
            idempotency_key,
        } = request;
        let context = request_context.canonical().invocation();
        let tenant_mode = request_context.canonical().tenant_mode();
        if context.authorization() != Decision::Allow {
            return Err(ToolProtocolError::Rejected);
        }
        let Some(entry) = self.catalog.entry(&name) else {
            return Err(ToolProtocolError::Rejected);
        };
        if !entry
            .declaration
            .required_extensions()
            .iter()
            .all(|extension| request_context.negotiated_extensions().contains(extension))
        {
            return Err(ToolProtocolError::Rejected);
        }

        let name_authorization = ToolAuthorizationRequest {
            operation: ToolAuthorizationOperation::Call,
            request_context: &request_context,
            declaration: &entry.declaration,
            input: None,
        };
        if self.authorizer.authorize(name_authorization).await == ToolAuthorizationDecision::Deny {
            return Err(ToolProtocolError::Rejected);
        }
        if entry.declaration.input_schema().validate(&input).is_err() {
            return Err(ToolProtocolError::InvalidRequest);
        }

        let resolved_authorization = ToolAuthorizationRequest {
            operation: ToolAuthorizationOperation::Call,
            request_context: &request_context,
            declaration: &entry.declaration,
            input: Some(&input),
        };
        if self.authorizer.authorize(resolved_authorization).await
            == ToolAuthorizationDecision::Deny
        {
            return Err(ToolProtocolError::Rejected);
        }

        let invocation = CapabilityInvocation::new(
            entry.declaration.capability().clone(),
            context.clone(),
            tenant_mode,
            input,
            confirmation,
            idempotency_key,
        );
        let output = match self
            .kernel
            .invoke(McpDispatchRequest::new(
                request_context.metadata().clone(),
                McpPrimitive::Tool,
                invocation,
            ))
            .await
        {
            Ok(result) => result.into_output(),
            Err(error) => return Ok(failure(map_dispatch_error(error.code()))),
        };
        if entry.declaration.output_schema().validate(&output).is_err() {
            return Ok(failure(ToolFailureCode::Internal));
        }
        Ok(CanonicalToolResult::success(
            ToolRepresentation::structured_only(output),
        ))
    }
}

impl fmt::Debug for ToolProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolProjection([redacted])")
    }
}

fn map_dispatch_error(code: McpDispatchErrorCode) -> ToolFailureCode {
    match code {
        McpDispatchErrorCode::InvalidRequest => ToolFailureCode::InvalidRequest,
        McpDispatchErrorCode::Rejected => ToolFailureCode::Rejected,
        McpDispatchErrorCode::Unavailable => ToolFailureCode::Unavailable,
        McpDispatchErrorCode::Internal => ToolFailureCode::Internal,
    }
}

fn failure(code: ToolFailureCode) -> CanonicalToolResult {
    CanonicalToolResult::error(ToolFailure::new(code))
}
