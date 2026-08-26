//! Durable, restartable privacy lifecycle, immutable consent evidence, and moderation contracts.
//!
//! Lifecycle requests snapshot an independent bounded [`RequiredInventoryManifest`] after exact
//! adapter coverage is validated by [`InventoryRegistry`]. Workers reconcile that stable snapshot
//! under a PostgreSQL lease and monotonically increasing fence; a request can reach
//! [`LifecycleState::Completed`] only after every required adapter has produced typed, hashed
//! evidence. Missing adapters, timeouts, and typed failures retry or dead-letter without recording
//! raw provider payloads. Pending and active legal holds pause and fence destructive operations.
//!
//! Consent grants and withdrawals are append-only, document-versioned evidence records. Moderation
//! persists reports, evidence references, actions, appeals, policy versions, actor and subject
//! identities while requiring an injected [`PrivacyAuthorizer`] for every application action.
//! Transport and provider-specific semantics deliberately remain outside this crate.

#![forbid(unsafe_code)]

mod authorization;
mod consent;
mod inventory;
mod lifecycle;
mod moderation;
mod postgres;
mod types;

pub use authorization::{
    AuthorizationDenied, ConsentAuthorizationContext, ModerationAuthorizationAction,
    ModerationAuthorizationContext, PrivacyAuthorizationAction, PrivacyAuthorizer, PrivacyResource,
};
pub use consent::{
    ConsentDocumentKind, ConsentEvidenceFormat, ConsentId, ConsentPolicy, ConsentPolicyError,
    ConsentRecord, ConsentRule, ConsentSource, ConsentTransport, ConsentWithdrawal,
    ConsentWithdrawalId, ConsentWithdrawalRule, RecordConsent, WithdrawConsent,
};
pub use inventory::{
    AdapterEvidence, AdapterFailure, AdapterFailureCode, AdapterFuture, AdapterName, AdapterWork,
    ArtifactId, DataInventoryAdapter, EvidenceDigest, ExportManifest, ExportManifestEntry,
    InventoryCategory, InventoryDescriptor, InventoryEffect, InventoryRegistry,
    InventoryRegistryError, InventoryRequirement, RequiredInventoryManifest,
};
pub use lifecycle::{
    CreateLegalHold, CreateLifecycleRequest, DeadLetterCommand, LegalHoldBasis, LegalHoldId,
    LegalHoldRecord, LegalHoldState, LifecycleFailureCode, LifecycleKind, LifecycleLease,
    LifecycleRequest, LifecycleRequestId, LifecycleState, LifecycleTarget, PrivacyLifecycleJob,
    ReleaseLegalHold, RetryPolicy, RetryPolicyError, WorkerId,
};
pub use moderation::{
    AddModerationEvidence, AppealDecision, AppealDecisionId, AppealDecisionKind, AppealId,
    AppealRecord, AppealState, AutomatedModerationPolicy, AutomatedModerationPolicyError,
    DecideAppeal, EvidenceId, EvidenceKind, ModerationAction, ModerationActionId,
    ModerationActionKind, ModerationActorRole, ModerationDuration, ModerationEvidence,
    ModerationReport, RecordModerationAction, ReportId, ReportState, SubmitAppeal, SubmitReport,
};
pub use postgres::{PrivacyError, PrivacyStore, PrivacyStorePolicies, ReconcileResult};
pub use types::{
    ActorIdentity, Jurisdiction, ObjectReference, PolicyVersion, PrivacyValueError, ReasonCode,
};

#[cfg(any(test, feature = "test-support"))]
pub mod testing;
