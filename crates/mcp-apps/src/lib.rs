//! Transport-neutral security and lifecycle contracts for opt-in MCP Apps.
//!
//! The crate keeps Apps metadata adapter-private, requires exact request-scoped official
//! extension negotiation, binds every record and proof to canonical identity, verifies immutable
//! UI resources, and routes every App action through the canonical capability registry. Deployments
//! implement durable lifecycle, object-storage, audit, and replay ports; no bypass or in-memory
//! production fallback is provided.

/// Durable, auditable App lifecycle contracts.
pub mod lifecycle;
/// Signed, scoped App manifest admission.
pub mod manifest;
/// Correlated and replay-protected host messaging.
pub mod messaging;
/// Exact official extension negotiation.
pub mod negotiation;
/// Authorized App tool projections.
pub mod projection;
/// Immutable bounded UI resource delivery.
pub mod resource;

pub use lifecycle::{
    AppLifecycleKey, AppLifecyclePlan, AppLifecycleRecord, AppLifecycleRepository,
    AppLifecycleService, LifecycleAction, LifecycleAuditEvent, LifecycleCommitError,
    LifecycleError, LifecycleRepositoryError, LifecycleState,
};
pub use manifest::{
    APP_HTML_MEDIA_TYPE, AdmittedUiManifest, AppBinding, AppPermission, ClientAppSupport,
    CspPolicy, HostSecurityPolicy, MAX_UI_MANIFEST_BYTES, MAX_UI_RESOURCE_BYTES, ManifestError,
    ManifestSignatureVerifier, MessageContract, SandboxPolicy, SandboxToken,
    SignatureVerificationError, SignedUiManifest, UI_MANIFEST_SIGNATURE_DOMAIN, UiManifest,
    UiManifestAdmission, UiManifestEnvelope, UiResourceMetadata, canonical_resource_uri,
};
pub use messaging::{
    AppActionClaim, AppActionClaimResult, AppActionLease, AppActionLeaseDisposition,
    AppActionLeaseFinish, AppActionLeaseRepository, HostInvocationEvidence, HostMessageContext,
    HostMessageInvocation, HostMessageResponse, HostMessageService, InboundHostMessage,
    MessageError, MessageReplayError, MessageReplayKey,
};
pub use negotiation::{
    APPS_EXTENSION_ID, APPS_EXTENSION_REVISION, AppsNegotiationError, apps_extension, require_apps,
};
pub use projection::{AppToolProjection, AppToolProjectionInput, ProjectionError, ToolVisibility};
pub use resource::{
    ArtifactRepositoryError, ResourceError, UiArtifactLocator, UiArtifactRead,
    UiArtifactRepository, UiResourceContents, UiResourceLocator, UiResourceService, sha256_digest,
};
