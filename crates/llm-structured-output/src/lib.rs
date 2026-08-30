//! Provider-neutral structured-output admission and bounded repair.
//!
//! Schemas are compiled locally as JSON Schema Draft 2020-12 before a provider
//! adapter may consume a prepared request. Completed JSON values are successful
//! only after the same local validator accepts them. This crate deliberately does
//! not define streaming events or accept JSON fragments as completed values.

mod bounded_json;
mod json_shape;
mod plan;
mod repair;
mod schema;

pub use plan::{
    FallbackPermission, PreparationError, PreparedStructuredOutput, StrategyDecision,
    StrategyPolicy, StrategySelectionError, StructuredOutputStrategy,
};
pub use repair::{
    CandidateInvalidKind, InvalidStructuredOutput, MAX_REPAIR_ATTEMPTS, RepairBudgetError,
    RepairCandidate, RepairMetering, RepairPolicy, RepairProviderFailure, RepairRequest,
    RepairToolPolicy, StructuredOutputError, StructuredOutputRepairPort, ValidatedStructuredOutput,
};
pub use schema::{SchemaGenerationError, schema_definition_for};
