//! Transport-neutral admission, package, isolation, projection, and lifecycle contracts for
//! experimental opt-in MCP Skills.
//!
//! Skills are signed but untrusted instructions, never capability or permission authorities.
//! Exact request-scoped extension negotiation comes only from
//! [`omnius_mcp_server_core::McpRequestContext`]. Every runtime read is data-only and backed by a
//! non-cloneable repository lease. Python, JavaScript, and WebAssembly declarations and reads are
//! rejected: this crate has no enforced executor and does not claim to sandbox executable content.
//! Every proof and durable record is bound to canonical tenant and principal identity plus
//! deployment-owned server and installation identity. No production in-memory fallback or
//! baseline/stable Skills enablement is provided.

/// Fail-closed future execution profile declarations.
pub mod isolation;
/// Audited lifecycle and repository-backed runtime leases.
pub mod lifecycle;
/// Signed provenance and capability-ceiling admission.
pub mod manifest;
/// Exact opt-in experimental extension negotiation.
pub mod negotiation;
/// Immutable bounded package inventory and resource reads.
pub mod package;
/// Authorized Skills discovery projections.
pub mod projection;

pub use isolation::{
    CredentialPolicy, ExecutableFormat, ExecutionProfile, FilesystemPolicy, IsolationError,
    NetworkPolicy, ProcessPolicy,
};
pub use lifecycle::{
    LifecycleAction, LifecycleAuditEvent, LifecycleCommitError, LifecycleError,
    LifecycleRepositoryError, LifecycleState, RepositoryLeaseFinish, RuntimeAdmissionError,
    RuntimeAuthorizationError, RuntimeEffectFenceHandle, RuntimeLeaseAcquireError,
    RuntimeLeaseFinish, RuntimeLeaseHandle, SkillLifecycleEffect, SkillLifecycleOperatorPolicy,
    SkillLifecyclePlan, SkillLifecycleRecord, SkillLifecycleRepository, SkillLifecycleService,
    SkillRuntimeAdmission, SkillRuntimeEffectFence, SkillRuntimeGrant, SkillRuntimeGuard,
    SkillRuntimeLeaseRequest,
};
pub use manifest::{
    AdmissionError, AdmittedSkill, AuthorizedSkillCapability, BindingError,
    CapabilityAuthorizationError, CapabilityRequest, MAX_EXTENSION_FIELDS, MAX_SKILL_CAPABILITIES,
    MAX_SKILL_MANIFEST_BYTES, MAX_UNTRUSTED_VALUE_DEPTH, MAX_UNTRUSTED_VALUE_NODES,
    ManifestSignatureVerifier, RevocationRepositoryError, RevocationStatus,
    SignatureVerificationError, SignedSkillManifest, SkillAdmissionService, SkillBinding,
    SkillExposure, SkillManifest, SkillPrincipalPolicy, SkillProvenance, SkillRevocationRepository,
    SkillServerIdentity, SkillTrustStore, TrustStatus, TrustStoreError, authorize_capabilities,
    declared_executable_formats,
};
pub use negotiation::{
    NegotiationError, SKILLS_EXTENSION_ID, SKILLS_EXTENSION_REVISION, SkillsExtensionPolicy,
    skills_extension,
};
pub use package::{
    ArtifactRepositoryError, InventoryError, MAX_SKILL_FILES, MAX_SKILL_PACKAGE_BYTES,
    PackageEntry, PackageEntryType, PackageFileKind, PackageReadError, SKILL_INSTRUCTIONS_PATH,
    SkillArtifactLocator, SkillArtifactMetadata, SkillArtifactRead, SkillArtifactRepository,
    SkillFileContents, SkillPackageService, VerifiedSkillPackage, inventory_digest,
    is_safe_relative_path, sha256_digest, validate_inventory,
};
pub use projection::{ProjectionError, SkillDescriptor, SkillFileDescriptor};
