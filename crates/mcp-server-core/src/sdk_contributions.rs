//! Leaf-neutral RMCP application contribution contracts.

use std::{future::Future, pin::Pin, sync::Arc};

use rmcp::{
    ErrorData,
    model::{
        CallToolRequestParams, CallToolResponse, CancelTaskParams, GetPromptRequestParams,
        GetPromptResult, GetTaskParams, GetTaskResult, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
        ReadResourceRequestParams, ReadResourceResult, SubscriptionFilter, TaskAckResult,
        UpdateTaskParams,
    },
    service::SubscriptionContext,
};
use thiserror::Error;

use crate::{McpDispatch, McpExposureFilter, McpKernel, McpRequestContext};

use crate::sdk::CanonicalContextResolver;

/// Boxed future returned by an object-safe RMCP application adapter.
pub type McpAdapterFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ErrorData>> + Send + 'a>>;

/// Exact MCP operation presented to the application operation guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpOperation {
    /// Enumerate authorized tools.
    ListTools,
    /// Invoke one authorized tool.
    CallTool,
    /// Enumerate authorized resources.
    ListResources,
    /// Enumerate authorized resource templates.
    ListResourceTemplates,
    /// Read one authorized resource.
    ReadResource,
    /// Enumerate authorized prompts.
    ListPrompts,
    /// Resolve one authorized prompt.
    GetPrompt,
    /// Establish a task subscription.
    Listen,
    /// Read task state.
    GetTask,
    /// Supply task input.
    UpdateTask,
    /// Cancel a task.
    CancelTask,
}

/// Request-scoped tenant guard applied after canonical-context resolution.
pub trait McpTenantGuard: Send + Sync {
    /// Returns `true` only when canonical tenant evidence is currently admissible.
    fn authorize(&self, context: &McpRequestContext) -> bool;
}

/// Request-scoped operation guard applied before every adapter.
pub trait McpOperationGuard: Send + Sync {
    /// Returns `true` only when the exact operation is currently admissible.
    fn authorize(&self, context: &McpRequestContext, operation: McpOperation) -> bool;
}

/// Exact RMCP tools projection backed by canonical application dispatch.
pub trait McpToolAdapter: Send + Sync {
    /// Enumerates authorized tools.
    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListToolsResult>;

    /// Invokes one authorized tool.
    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, CallToolResponse>;
}

/// Exact RMCP resources projection backed by canonical application dispatch.
pub trait McpResourceAdapter: Send + Sync {
    /// Enumerates authorized exact resources.
    fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListResourcesResult>;

    /// Enumerates authorized resource templates.
    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListResourceTemplatesResult>;

    /// Reads one authorized resource.
    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ReadResourceResult>;
}

/// Exact RMCP prompts projection backed by canonical application dispatch.
pub trait McpPromptAdapter: Send + Sync {
    /// Enumerates authorized prompts.
    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListPromptsResult>;

    /// Resolves one authorized prompt.
    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, GetPromptResult>;
}

/// Exact RMCP task-subscription projection.
pub trait McpSubscriptionAdapter: Send + Sync {
    /// Returns the exact supported subset of a requested notification filter.
    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter>;

    /// Runs one admitted subscription until cancellation, disconnect, or drain.
    fn listen(&self, context: SubscriptionContext) -> McpAdapterFuture<'_, ()>;
}

/// Exact RMCP Tasks extension projection.
pub trait McpTaskAdapter: Send + Sync {
    /// Reads current task state.
    fn get_task(
        &self,
        request: GetTaskParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, GetTaskResult>;

    /// Supplies input for a waiting task.
    fn update_task(
        &self,
        request: UpdateTaskParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, TaskAckResult>;

    /// Requests cooperative task cancellation.
    fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, TaskAckResult>;
}

/// Stable required application contribution identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpRequiredContribution {
    /// Canonical capability registry kernel.
    CapabilityRegistry,
    /// Canonical dispatch boundary.
    CapabilityDispatch,
    /// Authorization-filtered exposure registry.
    ExposureFilter,
    /// Bearer-authenticated HTTP context resolver.
    BearerAuthenticator,
    /// Tenant guard.
    TenantGuard,
    /// Operation guard.
    OperationGuard,
}

impl McpRequiredContribution {
    /// Returns the stable application-requirement literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityRegistry | Self::ExposureFilter => "mcp.capability-registry",
            Self::CapabilityDispatch | Self::OperationGuard => "mcp.capability-executor",
            Self::BearerAuthenticator => "mcp.bearer-authenticator",
            Self::TenantGuard => "mcp.subscription-authorizer",
        }
    }
}

/// Fail-closed application-contribution construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("required MCP application contribution `{contribution}` is missing", contribution = .contribution.as_str())]
pub struct McpApplicationContributionsError {
    contribution: McpRequiredContribution,
}

impl McpApplicationContributionsError {
    /// Returns the missing typed contribution.
    #[must_use]
    pub const fn contribution(self) -> McpRequiredContribution {
        self.contribution
    }
}

/// Required HTTP policy boundaries and selected primitive adapters for one MCP protocol handler.
#[derive(Clone)]
pub struct McpApplicationContributions {
    pub(crate) kernel: McpKernel,
    pub(crate) dispatch: Arc<dyn McpDispatch>,
    pub(crate) exposure_filter: McpExposureFilter,
    pub(crate) bearer_authenticator: Arc<dyn CanonicalContextResolver>,
    pub(crate) tenant_guard: Arc<dyn McpTenantGuard>,
    pub(crate) operation_guard: Arc<dyn McpOperationGuard>,
    pub(crate) tools: Option<Arc<dyn McpToolAdapter>>,
    pub(crate) resources: Option<Arc<dyn McpResourceAdapter>>,
    pub(crate) prompts: Option<Arc<dyn McpPromptAdapter>>,
    pub(crate) subscriptions: Option<Arc<dyn McpSubscriptionAdapter>>,
    pub(crate) tasks: Option<Arc<dyn McpTaskAdapter>>,
}

/// Fail-closed builder for [`McpApplicationContributions`].
#[derive(Default)]
pub struct McpApplicationContributionsBuilder {
    kernel: Option<McpKernel>,
    dispatch: Option<Arc<dyn McpDispatch>>,
    exposure_filter: Option<McpExposureFilter>,
    bearer_authenticator: Option<Arc<dyn CanonicalContextResolver>>,
    tenant_guard: Option<Arc<dyn McpTenantGuard>>,
    operation_guard: Option<Arc<dyn McpOperationGuard>>,
    tools: Option<Arc<dyn McpToolAdapter>>,
    resources: Option<Arc<dyn McpResourceAdapter>>,
    prompts: Option<Arc<dyn McpPromptAdapter>>,
    subscriptions: Option<Arc<dyn McpSubscriptionAdapter>>,
    tasks: Option<Arc<dyn McpTaskAdapter>>,
}

macro_rules! contribution_setter {
    ($name:ident, $field:ident, $type:ty, $documentation:literal) => {
        #[doc = $documentation]
        #[must_use]
        pub fn $name(mut self, value: $type) -> Self {
            self.$field = Some(value);
            self
        }
    };
}

impl McpApplicationContributionsBuilder {
    /// Starts an empty builder. [`Self::finish`] rejects it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    contribution_setter!(
        kernel,
        kernel,
        McpKernel,
        "Supplies the canonical capability registry kernel."
    );
    contribution_setter!(
        dispatch,
        dispatch,
        Arc<dyn McpDispatch>,
        "Supplies the canonical dispatch boundary."
    );
    contribution_setter!(
        exposure_filter,
        exposure_filter,
        McpExposureFilter,
        "Supplies authorization-filtered discovery."
    );
    contribution_setter!(
        bearer_authenticator,
        bearer_authenticator,
        Arc<dyn CanonicalContextResolver>,
        "Supplies bearer-authenticated HTTP context resolution."
    );
    contribution_setter!(
        tenant_guard,
        tenant_guard,
        Arc<dyn McpTenantGuard>,
        "Supplies canonical tenant admission."
    );
    contribution_setter!(
        operation_guard,
        operation_guard,
        Arc<dyn McpOperationGuard>,
        "Supplies operation admission."
    );
    contribution_setter!(
        tools,
        tools,
        Arc<dyn McpToolAdapter>,
        "Supplies the exact tools projection."
    );
    contribution_setter!(
        resources,
        resources,
        Arc<dyn McpResourceAdapter>,
        "Supplies the exact resources projection."
    );
    contribution_setter!(
        prompts,
        prompts,
        Arc<dyn McpPromptAdapter>,
        "Supplies the exact prompts projection."
    );
    contribution_setter!(
        subscriptions,
        subscriptions,
        Arc<dyn McpSubscriptionAdapter>,
        "Supplies task subscriptions."
    );
    contribution_setter!(
        tasks,
        tasks,
        Arc<dyn McpTaskAdapter>,
        "Supplies the Tasks extension."
    );

    /// Validates and returns the bearer-authenticated HTTP contribution bundle.
    ///
    /// # Errors
    ///
    /// Returns the first missing stable policy contribution in construction order. Primitive
    /// adapters remain absent unless explicitly selected; no fallback adapter or policy is installed.
    pub fn finish(self) -> Result<McpApplicationContributions, McpApplicationContributionsError> {
        macro_rules! required {
            ($field:expr, $kind:ident) => {
                $field.ok_or(McpApplicationContributionsError {
                    contribution: McpRequiredContribution::$kind,
                })?
            };
        }

        Ok(McpApplicationContributions {
            kernel: required!(self.kernel, CapabilityRegistry),
            dispatch: required!(self.dispatch, CapabilityDispatch),
            exposure_filter: required!(self.exposure_filter, ExposureFilter),
            bearer_authenticator: required!(self.bearer_authenticator, BearerAuthenticator),
            tenant_guard: required!(self.tenant_guard, TenantGuard),
            operation_guard: required!(self.operation_guard, OperationGuard),
            tools: self.tools,
            resources: self.resources,
            prompts: self.prompts,
            subscriptions: self.subscriptions,
            tasks: self.tasks,
        })
    }
}
