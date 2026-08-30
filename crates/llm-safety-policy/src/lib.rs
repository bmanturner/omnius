//! Provider-neutral LLM data handling and confused-deputy safety policy.
//!
//! This crate owns content-free policy facts. Prompt text, model output, tool
//! arguments, schemas, credentials, provider bodies, tenant values, and principal
//! values stay outside these contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod boundary;
mod classification;
mod diagnostics;
mod facts;
mod inventory;

pub use boundary::{
    BoundaryDecision, ContentPlacement, ContentProvenance, EgressAuthority, ExecutionRestrictions,
    ExecutionSafetyContext, InjectionIndicator, InstructionSource, ProvenanceDigest,
    ProvenanceError, Restriction, ToolAuthority, ToolAuthorityError, UntrustedSource,
};
pub use classification::{
    ArtifactClassifications, ArtifactKind, ArtifactPolicyError, ContentFreeTelemetryFacts,
    DataClassification, DataHandlingPolicy, TelemetryPolicy,
};
pub use diagnostics::{
    DiagnosticAdmissionError, DiagnosticCaptureAdmission, DiagnosticCaptureRequest,
    MAX_DIAGNOSTIC_CAPTURE_SAMPLES, MAX_DIAGNOSTIC_CAPTURE_WINDOW,
};
pub use facts::{
    ContentFreeContextFacts, ContentFreeProviderCacheFacts, ContextTruncationOutcome,
    ProviderCacheOutcome, SafetyAuditAdapter, SafetyAuditEvent, SafetyAuditFact, SafetyReasonCode,
};
pub use inventory::{
    AdapterEvidence, AdapterFailure, AdapterFailureCode, AdapterFuture, AdapterName, AdapterWork,
    DataInventoryAdapter, EvidenceDigest, InventoryCategory, InventoryDescriptor, InventoryEffect,
    InventoryRequirement, LifecycleKind, LifecycleRequestId, LlmInventoryKind, LlmInventoryPlan,
    LlmInventoryPlanError, LlmInventoryRequirement, PrivacyInventoryRegistry,
    PrivacyInventoryRegistryError, RequiredInventoryManifest,
};
