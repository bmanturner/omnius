//! Stateless, authenticated MCP multi-round-trip elicitation.
//!
//! The crate owns bounded elicitation plans, minimal signed request-state handles, atomic replay
//! claims, local response validation, redacted audit events, and reinvocation through the existing
//! capability registry boundary. It deliberately owns no MCP session, task persistence, business
//! execution path, or production in-memory durability.

#![forbid(unsafe_code)]

mod model;
mod ports;
mod postgres;
mod service;
mod state;

/// Pinned RMCP conversion and duplicate-aware wire parsing.
pub mod wire;

pub use model::{
    BindingDigest, ClaimResult, ClientElicitationCapabilities, ConfigError, DeclineBehavior,
    ElicitationChallenge, ElicitationPlan, FieldPlan, FormElicitationPlan, FormProtection,
    InputRequestKey, InputResponseMap, InvocationBinding, InvocationContinuation,
    InvocationDisposition, MAX_FORM_FIELDS, MAX_INPUT_REQUESTS, MAX_MRTR_ROUNDS,
    MAX_REQUEST_STATE_TTL, MRTR_EXTENSION_ID, MRTR_EXTENSION_REVISION, MrtrAuditEvent,
    MrtrAuditKind, MrtrConfig, MrtrCorrelation, MrtrMethod, NormalInvocationRequest,
    OriginalInvocation, PendingMrtrState, PlanError, PlannedElicitation, ReplacementReason,
    RequestStateToken, ResumeOutcome, Sensitivity, StateBinding, StateClaim, TerminalStatus,
    UrlElicitationPlan,
};
pub use ports::{InvocationError, MrtrStateRepository, NormalInvocationPort, RepositoryError};
pub use postgres::PostgresMrtrStateRepository;
pub use service::{BeginRequest, LifecycleError, MrtrService, ResumeRequest};
