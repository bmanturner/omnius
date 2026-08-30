//! Authorized request-local execution of registry-derived LLM tools.
//!
//! [`ToolCatalog`] exposes only available capability documents that declare
//! `Exposure::LlmTool`. [`ToolRuntime`] accepts only complete canonical tool calls,
//! obtains exact authorization through a fail-closed port, applies every policy
//! guard, and dispatches exclusively through the shared capability registry.
//! [`AgentLoopBudget`] owns deterministic limits for model and tool orchestration.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod budget;
mod call;
mod catalog;
mod runtime;

pub use budget::{
    AgentLoopBudget, LoopBudgetBuildError, LoopBudgetDimension, LoopBudgetError, LoopBudgetLimits,
    LoopBudgetSnapshot, LoopConcurrencyPermit,
};
pub use call::{CompleteToolCall, CompleteToolCallError, ExecutedToolResult, ToolCallIdentity};
pub use catalog::{CatalogTool, ToolCatalog, ToolCatalogError};
pub use runtime::{
    AuthorizedToolInvocation, SideEffectApproval, ToolAuditError, ToolAuditOutcome, ToolAuditPort,
    ToolAuditRecord, ToolAuthorizationBinding, ToolAuthorizationError, ToolAuthorizationPort,
    ToolAuthorizationRequest, ToolExecutionEvidence, ToolRuntime, ToolRuntimeBuildError,
    ToolRuntimeError, ToolRuntimeLimits,
};
