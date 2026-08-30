//! One immutable, transport-independent registry for guarded application capabilities.
//!
//! Capability metadata, canonical context, authorization and tenancy guardrails,
//! deadline/cancellation handling, and handler dispatch live here. HTTP, jobs, LLM
//! tools, MCP projections, and browser adapters supply only an [`Exposure`] and a
//! [`CapabilityInvocation`]; none receives a separate behavior path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod context;
mod metadata;
mod registry;
mod value;

pub use context::{
    BudgetBounds, BudgetError, ContextError, InvocationContext, MAX_INPUT_BUDGET_BYTES,
    MAX_OUTPUT_BUDGET_BYTES, MAX_WORK_UNITS,
};
pub use metadata::{
    CapabilityDocument, CapabilityKey, CapabilityKind, ConfirmationPolicy, DeclarationError,
    Exposure, IdempotencyPolicy, JSON_SCHEMA_DRAFT_2020_12, MAX_EXPOSURES, MAX_PERMISSIONS,
    MAX_SCHEMA_BYTES, MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES, MAX_TENANT_MODES, ObjectSchema,
    SchemaValueError, SideEffect, TenantMode,
};
pub use registry::{
    AvailabilityReason, AvailabilitySnapshot, CapabilityAvailability, CapabilityHandler,
    CapabilityInvocation, CapabilityRegistry, CapabilityRegistryBuilder, ConfirmationEvidence,
    HandlerError, HandlerErrorCode, HandlerInvocation, InvocationError, InvocationResult,
    RegistryBuildError, RuntimeAvailability,
};
pub use value::{
    CapabilityDescription, CapabilityId, CapabilityTitle, CapabilityVersion, DataPolicyRef,
    IdempotencyKey, MAX_CAPABILITY_ID_BYTES, MAX_CAPABILITY_VERSION_BYTES,
    MAX_DATA_POLICY_REF_BYTES, MAX_DESCRIPTION_BYTES, MAX_IDEMPOTENCY_KEY_BYTES,
    MAX_PERMISSION_BYTES, MAX_TITLE_BYTES, MAX_TRACE_STATE_BYTES, MAX_TRACE_STATE_MEMBERS,
    Permission, TraceContext, TraceParent, TraceState, ValueError,
};
