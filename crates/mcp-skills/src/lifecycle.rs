use std::{collections::BTreeSet, fmt};

use omnius_agent_capability_registry::{CapabilityKey, CapabilityRegistry};
use omnius_auth_core::SubjectId;
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::manifest::{
    AdmittedSkill, AuthorizedSkillCapability, BindingError, CapabilityAuthorizationError,
    SkillBinding, SkillPrincipalPolicy, SkillProvenance, SkillServerIdentity,
    authorize_capabilities,
};
use crate::negotiation::{
    NegotiationError, SKILLS_EXTENSION_ID, SKILLS_EXTENSION_REVISION, SkillsExtensionPolicy,
};
use crate::package::VerifiedSkillPackage;

/// Durable Skill lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Installed and default-off.
    Installed,
    /// Explicitly enabled after current trust, revocation, registry, and policy checks.
    Enabled,
    /// Explicitly disabled with every runtime projection removed.
    Disabled,
    /// Uninstalled with runtime projections and package objects removed.
    Uninstalled,
}

/// Authoritative record for one exact canonical binding and immutable package revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillLifecycleRecord {
    /// Stable extension identity.
    pub extension_id: String,
    /// Exact experimental extension revision.
    pub extension_revision: String,
    /// Canonical tenant, principal, server, and installation binding.
    pub binding: SkillBinding,
    /// Versioned Skill URI.
    pub skill_uri: String,
    /// Semantic Skill version.
    pub version: String,
    /// Verified immutable package digest.
    pub package_digest: String,
    /// Verified signed-manifest provenance.
    pub provenance: SkillProvenance,
    /// Exact registry capability revisions admitted for this immutable package.
    pub capability_keys: BTreeSet<CapabilityKey>,
    /// Current lifecycle state.
    pub state: LifecycleState,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
}

impl SkillLifecycleRecord {
    /// Requires a freshly loaded enabled record matching every admitted identity and provenance field.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::Disabled`] unless the record is enabled, or
    /// [`LifecycleError::InvalidInput`] when any immutable admission field differs.
    pub fn require_enabled(&self, admitted: &AdmittedSkill) -> Result<(), LifecycleError> {
        let manifest = admitted.manifest();
        if self.state != LifecycleState::Enabled {
            return Err(LifecycleError::Disabled);
        }
        if self.extension_id != SKILLS_EXTENSION_ID
            || self.extension_revision != SKILLS_EXTENSION_REVISION
            || self.binding != *admitted.binding()
            || self.skill_uri != manifest.uri.as_str()
            || self.version != manifest.version
            || self.package_digest != manifest.package_digest
            || self.provenance != *admitted.provenance()
            || self.capability_keys != capability_keys(admitted.capabilities())
        {
            return Err(LifecycleError::InvalidInput);
        }
        Ok(())
    }
}

/// Operator lifecycle action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    /// Install an admitted and verified package default-off.
    Install,
    /// Enable after an atomic current trust/revocation check.
    Enable,
    /// Disable and remove every runtime projection.
    Disable,
    /// Uninstall and remove every runtime projection and package object.
    Uninstall,
}

/// Repository effects implied by a valid lifecycle transition.
///
/// The closed variants prevent repository implementations from observing invalid combinations of
/// independent booleans, such as removing a package without fencing active runtime leases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillLifecycleEffect {
    /// Recheck current signer trust and revocation without removing runtime state.
    RecheckAdmission,
    /// Fence active leases and remove every runtime projection.
    FenceAndRemoveRuntimeProjection,
    /// Fence active leases and remove runtime projections plus immutable package objects.
    FenceAndRemoveRuntimeProjectionAndPackage,
}

impl SkillLifecycleEffect {
    /// Returns whether the commit must recheck current signer trust and revocation.
    #[must_use]
    pub const fn requires_current_admission(self) -> bool {
        matches!(self, Self::RecheckAdmission)
    }

    /// Returns whether the commit must remove discovery projections.
    #[must_use]
    pub const fn removes_runtime_projection(self) -> bool {
        matches!(
            self,
            Self::FenceAndRemoveRuntimeProjection | Self::FenceAndRemoveRuntimeProjectionAndPackage
        )
    }

    /// Returns whether the commit must cancel and generation-fence matching runtime leases.
    #[must_use]
    pub const fn fences_runtime_leases(self) -> bool {
        self.removes_runtime_projection()
    }

    /// Returns whether the commit must remove every immutable package object.
    #[must_use]
    pub const fn removes_package(self) -> bool {
        matches!(self, Self::FenceAndRemoveRuntimeProjectionAndPackage)
    }
}

/// Deployment policy boundary for every operator-initiated Skill lifecycle change.
pub trait SkillLifecycleOperatorPolicy {
    /// Returns the current operator-policy decision for one exact binding, Skill, and action.
    fn authorize(
        &self,
        request: &McpRequestContext,
        binding: &SkillBinding,
        skill_uri: &str,
        action: LifecycleAction,
    ) -> Decision;
}

/// Fixed-field audit event that cannot carry instructions, content, tokens, or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAuditEvent {
    /// Exact extension identity.
    pub extension_id: String,
    /// Exact experimental extension revision.
    pub extension_revision: String,
    /// Canonical security binding.
    pub binding: SkillBinding,
    /// Versioned Skill identity.
    pub skill_uri: String,
    /// Semantic version.
    pub version: String,
    /// Integrity-only package digest.
    pub package_digest: String,
    /// Digest and signer provenance without package or instruction content.
    pub provenance: SkillProvenance,
    /// Exact capability revisions retained for audit.
    pub capability_keys: BTreeSet<CapabilityKey>,
    /// Canonical authenticated operator identity.
    pub actor_id: SubjectId,
    /// Applied action.
    pub action: LifecycleAction,
    /// Previous state, absent only for install.
    pub previous_state: Option<LifecycleState>,
    /// Resulting state.
    pub state: LifecycleState,
    /// Resulting repository revision.
    pub revision: u64,
}

/// Atomic authoritative change, mandatory audit event, removal effects, and runtime-lease fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillLifecyclePlan {
    /// Expected compare-and-swap revision; zero requires absence.
    pub expected_revision: u64,
    /// Complete next record, including an uninstall tombstone when applicable.
    pub next: SkillLifecycleRecord,
    /// Audit event appended in the same transaction.
    pub audit: LifecycleAuditEvent,
    /// Closed set of required admission, runtime-fencing, projection, and package effects.
    ///
    /// If the effect fences matching leases and a lease or committed effect fence remains active,
    /// `commit` must return [`LifecycleCommitError::LeasesActive`] without storing `next` or
    /// appending `audit`. The generation fence remains in place, preventing new leases, until a
    /// retry commits the plan.
    pub effect: SkillLifecycleEffect,
}

/// Durable canonical-binding lifecycle, admission guard, runtime leases, removal, and audit boundary.
pub trait SkillLifecycleRepository: Send + Sync {
    /// Loads by complete binding plus versioned Skill URI.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleRepositoryError`] when authoritative state cannot be loaded.
    fn load(
        &self,
        binding: &SkillBinding,
        skill_uri: &str,
    ) -> Result<Option<SkillLifecycleRecord>, LifecycleRepositoryError>;

    /// Atomically rechecks admission when required, compares revision, fences matching leases,
    /// applies removals, stores, and audits.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleCommitError`] when compare-and-swap, current admission, active leases,
    /// durable removals, state storage, or audit append prevents the atomic commit.
    fn commit(&self, plan: &SkillLifecyclePlan) -> Result<(), LifecycleCommitError>;

    /// Atomically acquires a live non-cloneable lease for the exact enabled record.
    ///
    /// The repository must compare every field in `request.record`, its lifecycle revision, exact
    /// capability revisions, and `revocation_revision` with current durable state in one critical
    /// section. It must reject a pending lifecycle fence, register the returned handle before
    /// leaving that section, and derive its cancellation token from the matching lifecycle
    /// generation. Trust or revocation changes must generation-fence and cancel matching handles.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeLeaseAcquireError`] when the enabled record is stale or disabled, current
    /// admission is denied, a lifecycle fence is pending, or the repository is unavailable.
    fn acquire_runtime_lease(
        &self,
        request: &SkillRuntimeLeaseRequest<'_>,
    ) -> Result<Box<dyn RuntimeLeaseHandle>, RuntimeLeaseAcquireError>;
}

/// Runtime trust and revocation boundary checked before atomic repository lease acquisition.
pub trait SkillRuntimeAdmission: Send + Sync {
    /// Returns the current non-zero revocation generation for the exact record.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAdmissionError`] when current trust or revocation cannot authorize the
    /// exact lifecycle record.
    fn current_revocation_revision(
        &self,
        record: &SkillLifecycleRecord,
    ) -> Result<u64, RuntimeAdmissionError>;
}

/// Redacted runtime trust/revocation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill runtime admission or revocation decision denied")]
pub struct RuntimeAdmissionError;

/// Complete atomic runtime-lease acquisition request.
#[derive(Clone, Copy, Debug)]
pub struct SkillRuntimeLeaseRequest<'a> {
    /// Freshly loaded full immutable Skill binding and enabled lifecycle record.
    pub record: &'a SkillLifecycleRecord,
    /// Current non-zero revocation generation returned by the admission authority.
    pub revocation_revision: u64,
    /// Fresh registry and principal-policy capability intersection.
    pub capabilities: &'a [AuthorizedSkillCapability],
}

/// Repository runtime-lease acquisition rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeLeaseAcquireError {
    /// Lifecycle state, revision, immutable package fields, or capability revisions changed.
    #[error("Skill runtime lease state is disabled or stale")]
    Disabled,
    /// Trust or current revocation generation denied acquisition.
    #[error("Skill runtime lease admission denied")]
    AdmissionDenied,
    /// A disable, uninstall, or revocation fence prevents new leases.
    #[error("Skill runtime lease is fenced")]
    Fenced,
    /// Durable lease registration was unavailable.
    #[error("Skill runtime lease repository unavailable")]
    Unavailable,
}

/// Repository-owned active lease handle.
///
/// Dropping a handle must release its active lease. `finish` must atomically recheck the exact
/// lifecycle generation and current revocation generation. A committed result must retain a
/// repository fence that prevents final lifecycle state changes until the caller's effect closes.
pub trait RuntimeLeaseHandle: Send + Sync {
    /// Borrows the child token cancelled by disable, uninstall, or revocation fencing.
    fn cancellation_token(&self) -> &CancellationToken;

    /// Rechecks the lease and either grants an effect fence or reports why no effect may commit.
    fn finish(self: Box<Self>) -> RepositoryLeaseFinish;
}

/// Repository result of finishing an active runtime lease.
pub enum RepositoryLeaseFinish {
    /// Current generation and revocation remain valid; the fence stays active through the effect.
    Committed(Box<dyn RuntimeEffectFenceHandle>),
    /// The caller deliberately completed without an external effect.
    Aborted,
    /// Lifecycle generation, revocation, or cancellation fenced the lease.
    Fenced,
}

impl fmt::Debug for RepositoryLeaseFinish {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(_) => formatter.write_str("Committed([redacted])"),
            Self::Aborted => formatter.write_str("Aborted"),
            Self::Fenced => formatter.write_str("Fenced"),
        }
    }
}

/// Repository fence held across one final capability or external effect.
///
/// Dropping without `commit` must abort and release it. The repository must not commit a matching
/// disable/uninstall final state while this handle is live.
pub trait RuntimeEffectFenceHandle: Send {
    /// Records successful effect completion and releases the repository fence.
    fn commit(self: Box<Self>);
}

/// Public outcome of finishing a non-cloneable runtime lease.
pub enum RuntimeLeaseFinish {
    /// The caller may perform one final effect only through this live fence.
    Committed(Box<SkillRuntimeEffectFence>),
    /// The lease ended without an effect.
    Aborted,
    /// Lifecycle or revocation changed; no effect may occur.
    Fenced,
}

impl fmt::Debug for RuntimeLeaseFinish {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(_) => formatter.write_str("Committed([redacted])"),
            Self::Aborted => formatter.write_str("Aborted"),
            Self::Fenced => formatter.write_str("Fenced"),
        }
    }
}

/// Live repository fence for exactly one final capability or external effect.
pub struct SkillRuntimeEffectFence {
    binding: SkillBinding,
    skill_uri: String,
    version: String,
    package_digest: String,
    provenance: SkillProvenance,
    lifecycle_revision: u64,
    revocation_revision: u64,
    cancellation: CancellationToken,
    capabilities: Vec<AuthorizedSkillCapability>,

    handle: Option<Box<dyn RuntimeEffectFenceHandle>>,
}

impl SkillRuntimeEffectFence {
    /// Borrows the exact canonical binding retained by this effect fence.
    #[must_use]
    pub const fn binding(&self) -> &SkillBinding {
        &self.binding
    }

    /// Borrows the exact versioned Skill URI retained by this effect fence.
    #[must_use]
    pub fn skill_uri(&self) -> &str {
        &self.skill_uri
    }

    /// Borrows the immutable semantic version retained by this effect fence.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Borrows the immutable package digest retained by this effect fence.
    #[must_use]
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// Borrows signed provenance retained by this effect fence.
    #[must_use]
    pub const fn provenance(&self) -> &SkillProvenance {
        &self.provenance
    }

    /// Returns the lifecycle generation protected by this effect fence.
    #[must_use]
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the revocation generation protected by this effect fence.
    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }

    /// Runs one external effect while the repository fence prevents a final lifecycle cutover.
    ///
    /// The effect receives the fresh registry/policy capability intersection. A cancellation that
    /// won the race before this call returns [`RuntimeAuthorizationError::Fenced`] without running
    /// the effect. Once the effect starts, the repository fence prevents a matching final
    /// lifecycle state from committing until the effect returns and releases the fence.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorizationError::Fenced`] when lifecycle or revocation cancellation won
    /// before the effect started. In that case the closure is not called.
    pub fn commit_external_effect<T>(
        mut self,
        effect: impl FnOnce(&[AuthorizedSkillCapability]) -> T,
    ) -> Result<T, RuntimeAuthorizationError> {
        if self.cancellation.is_cancelled() {
            return Err(RuntimeAuthorizationError::Fenced);
        }
        let result = effect(&self.capabilities);
        if let Some(handle) = self.handle.take() {
            handle.commit();
        }
        Ok(result)
    }
}

impl fmt::Debug for SkillRuntimeEffectFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillRuntimeEffectFence([redacted])")
    }
}

/// Redacted lifecycle repository read failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill lifecycle repository read failed")]
pub struct LifecycleRepositoryError;

/// Atomic commit result.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LifecycleCommitError {
    /// Expected revision no longer matches authoritative state.
    #[error("Skill lifecycle revision conflict")]
    Conflict,
    /// Signer, signature, version, or package became untrusted or revoked before commit.
    #[error("Skill lifecycle admission denied")]
    AdmissionDenied,
    /// Matching runtime leases were cancelled/fenced but have not released yet.
    #[error("Skill lifecycle runtime leases are still active")]
    LeasesActive,
    /// Durable state, removals, or audit append failed.
    #[error("Skill lifecycle commit failed")]
    Unavailable,
}

/// Coordinates explicitly authorized, revision-safe, audited Skill transitions.
pub struct SkillLifecycleService<R, P> {
    repository: R,
    extension_policy: SkillsExtensionPolicy,
    operator_policy: P,
}

impl<R, P> SkillLifecycleService<R, P>
where
    R: SkillLifecycleRepository,
    P: SkillLifecycleOperatorPolicy,
{
    /// Creates a lifecycle service around deployment repository, extension, and operator policy.
    #[must_use]
    pub const fn new(
        repository: R,
        extension_policy: SkillsExtensionPolicy,
        operator_policy: P,
    ) -> Self {
        Self {
            repository,
            extension_policy,
            operator_policy,
        }
    }

    /// Installs an admitted, fully verified package default-off for the current canonical request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] when negotiation, canonical binding, operator authorization,
    /// package verification, repository availability, uniqueness, or the atomic commit fails.
    pub fn install(
        &self,
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        admitted: &AdmittedSkill,
        verified: &VerifiedSkillPackage,
    ) -> Result<SkillLifecycleRecord, LifecycleError> {
        self.extension_policy.require_skills(request)?;
        admitted.binding().require_request(server, request)?;
        require_lifecycle_authorized(
            request,
            &self.operator_policy,
            admitted.binding(),
            admitted.manifest().uri.as_str(),
            LifecycleAction::Install,
        )?;
        if !verified.matches_admitted(admitted) {
            return Err(LifecycleError::InvalidInput);
        }
        let manifest = admitted.manifest();
        let current = self
            .repository
            .load(admitted.binding(), manifest.uri.as_str())
            .map_err(|_| LifecycleError::Unavailable)?;
        if current.is_some() {
            return Err(LifecycleError::AlreadyInstalled);
        }
        let next = SkillLifecycleRecord {
            extension_id: SKILLS_EXTENSION_ID.to_owned(),
            extension_revision: SKILLS_EXTENSION_REVISION.to_owned(),
            binding: admitted.binding().clone(),
            skill_uri: manifest.uri.as_str().to_owned(),
            version: manifest.version.clone(),
            package_digest: manifest.package_digest.clone(),
            provenance: admitted.provenance().clone(),
            capability_keys: capability_keys(admitted.capabilities()),
            state: LifecycleState::Installed,
            revision: 1,
        };
        let plan = SkillLifecyclePlan {
            expected_revision: 0,
            audit: audit_event(
                None,
                &next,
                admitted.binding().principal_id(),
                LifecycleAction::Install,
            ),
            next,
            effect: SkillLifecycleEffect::RecheckAdmission,
        };
        self.repository.commit(&plan).map_err(map_commit_error)?;
        Ok(plan.next)
    }

    /// Applies an enable, disable, or uninstall transition under canonical identity and CAS.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] for invalid input or transitions, failed negotiation or canonical
    /// authorization, missing or stale state, repository failure, denied current admission, or
    /// active leases that prevent the atomic transition.
    pub fn transition(
        &self,
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        skill_uri: &str,
        expected_revision: u64,
        action: LifecycleAction,
    ) -> Result<SkillLifecycleRecord, LifecycleError> {
        if expected_revision == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        let effect = match action {
            LifecycleAction::Install => return Err(LifecycleError::InvalidInput),
            LifecycleAction::Enable => SkillLifecycleEffect::RecheckAdmission,
            LifecycleAction::Disable => SkillLifecycleEffect::FenceAndRemoveRuntimeProjection,
            LifecycleAction::Uninstall => {
                SkillLifecycleEffect::FenceAndRemoveRuntimeProjectionAndPackage
            }
        };
        if action == LifecycleAction::Enable {
            self.extension_policy.require_skills(request)?;
        }
        let binding = SkillBinding::from_request(server, request)?;
        require_lifecycle_authorized(request, &self.operator_policy, &binding, skill_uri, action)?;
        let current = self
            .repository
            .load(&binding, skill_uri)
            .map_err(|_| LifecycleError::Unavailable)?
            .ok_or(LifecycleError::NotInstalled)?;
        if current.extension_id != SKILLS_EXTENSION_ID
            || current.extension_revision != SKILLS_EXTENSION_REVISION
            || current.binding != binding
            || current.skill_uri != skill_uri
        {
            return Err(LifecycleError::InvalidInput);
        }
        if current.revision != expected_revision {
            return Err(LifecycleError::Conflict);
        }
        let next_state = next_state(current.state, action)?;
        let mut next = current.clone();
        next.state = next_state;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(LifecycleError::Conflict)?;
        let plan = SkillLifecyclePlan {
            expected_revision,
            audit: audit_event(Some(current.state), &next, binding.principal_id(), action),
            next,
            effect,
        };
        self.repository.commit(&plan).map_err(map_commit_error)?;
        Ok(plan.next)
    }
}

/// Non-cloneable request-scoped lease produced only after atomic repository registration.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRuntimeGrant {
    binding: SkillBinding,
    skill_uri: String,
    version: String,
    package_digest: String,
    provenance: SkillProvenance,
    lifecycle_revision: u64,
    revocation_revision: u64,
    capabilities: Vec<AuthorizedSkillCapability>,
    #[serde(skip)]
    lease: Option<Box<dyn RuntimeLeaseHandle>>,
}

impl SkillRuntimeGrant {
    /// Borrows the exact canonical binding.
    #[must_use]
    pub const fn binding(&self) -> &SkillBinding {
        &self.binding
    }

    /// Borrows the exact versioned Skill URI.
    #[must_use]
    pub fn skill_uri(&self) -> &str {
        &self.skill_uri
    }

    /// Borrows the immutable semantic version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Borrows the immutable package digest.
    #[must_use]
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// Borrows retained signature provenance.
    #[must_use]
    pub const fn provenance(&self) -> &SkillProvenance {
        &self.provenance
    }

    /// Returns the atomically leased authoritative lifecycle revision.
    #[must_use]
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the atomically leased current revocation generation.
    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }

    /// Iterates exact capability revisions as non-authoritative metadata.
    ///
    /// Capability use is available only from [`SkillRuntimeEffectFence::commit_external_effect`].
    pub fn capability_keys(&self) -> impl ExactSizeIterator<Item = &CapabilityKey> {
        self.capabilities.iter().map(AuthorizedSkillCapability::key)
    }

    /// Returns whether disable, uninstall, or revocation cancelled this lease.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.lease
            .as_ref()
            .is_none_or(|lease| lease.cancellation_token().is_cancelled())
    }

    /// Clones the child cancellation signal for cooperative in-flight work.
    #[must_use]
    pub fn child_cancellation_token(&self) -> CancellationToken {
        if let Some(lease) = &self.lease {
            return lease.cancellation_token().clone();
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        cancelled
    }

    /// Rejects use after lifecycle or revocation cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorizationError::Fenced`] after lifecycle or revocation cancellation,
    /// or after this non-cloneable lease has already been consumed.
    pub fn require_live(&self) -> Result<(), RuntimeAuthorizationError> {
        if self.is_cancelled() {
            return Err(RuntimeAuthorizationError::Fenced);
        }
        Ok(())
    }

    /// Atomically rechecks lifecycle generation and revocation before a final effect.
    ///
    /// A committed result still does not authorize detached execution. The caller must perform its
    /// single capability or external effect through the returned repository fence.
    #[must_use]
    pub fn finish(mut self) -> RuntimeLeaseFinish {
        let Some(lease) = self.lease.take() else {
            return RuntimeLeaseFinish::Fenced;
        };
        let cancellation = lease.cancellation_token().clone();
        if cancellation.is_cancelled() {
            return RuntimeLeaseFinish::Fenced;
        }
        match lease.finish() {
            RepositoryLeaseFinish::Committed(handle) => {
                RuntimeLeaseFinish::Committed(Box::new(SkillRuntimeEffectFence {
                    binding: self.binding,
                    skill_uri: self.skill_uri,
                    version: self.version,
                    package_digest: self.package_digest,
                    provenance: self.provenance,
                    lifecycle_revision: self.lifecycle_revision,
                    revocation_revision: self.revocation_revision,
                    cancellation,
                    capabilities: self.capabilities,
                    handle: Some(handle),
                }))
            }
            RepositoryLeaseFinish::Aborted => RuntimeLeaseFinish::Aborted,
            RepositoryLeaseFinish::Fenced => RuntimeLeaseFinish::Fenced,
        }
    }

    /// Releases the lease without authorizing an external effect.
    #[must_use]
    pub fn abort(self) -> RuntimeLeaseFinish {
        drop(self);
        RuntimeLeaseFinish::Aborted
    }

    /// Requires this lease to remain byte-for-byte bound to the admitted immutable package.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorizationError::ScopeMismatch`] when any immutable binding, package,
    /// provenance, or capability field differs, or [`RuntimeAuthorizationError::Fenced`] when the
    /// lease is no longer live.
    pub fn require_admitted(
        &self,
        admitted: &AdmittedSkill,
    ) -> Result<(), RuntimeAuthorizationError> {
        let manifest = admitted.manifest();
        if self.binding != *admitted.binding()
            || self.skill_uri != manifest.uri.as_str()
            || self.version != manifest.version
            || self.package_digest != manifest.package_digest
            || self.provenance != *admitted.provenance()
            || capability_keys(&self.capabilities) != capability_keys(admitted.capabilities())
        {
            return Err(RuntimeAuthorizationError::ScopeMismatch);
        }
        self.require_live()
    }

    pub(crate) fn capabilities(&self) -> &[AuthorizedSkillCapability] {
        &self.capabilities
    }
}

impl PartialEq for SkillRuntimeGrant {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.skill_uri == other.skill_uri
            && self.version == other.version
            && self.package_digest == other.package_digest
            && self.provenance == other.provenance
            && self.lifecycle_revision == other.lifecycle_revision
            && self.revocation_revision == other.revocation_revision
            && self.capabilities == other.capabilities
    }
}

impl Eq for SkillRuntimeGrant {}

impl fmt::Debug for SkillRuntimeGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillRuntimeGrant([redacted])")
    }
}

/// Shared current-state guard required by every Skills discovery or data-only artifact read.
pub struct SkillRuntimeGuard {
    extension_policy: SkillsExtensionPolicy,
}

impl SkillRuntimeGuard {
    /// Creates a guard using the explicit experimental Skills enablement policy.
    #[must_use]
    pub const fn new(extension_policy: SkillsExtensionPolicy) -> Self {
        Self { extension_policy }
    }

    /// Loads current policy and atomically registers a repository-backed runtime lease.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorizationError`] when negotiation, canonical binding, lifecycle state,
    /// immutable provenance, current registry/policy authority, admission, or atomic lease
    /// acquisition fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "each independent authority remains explicit at the runtime trust boundary"
    )]
    pub fn authorize(
        &self,
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        admitted: &AdmittedSkill,
        lifecycle_repository: &impl SkillLifecycleRepository,
        runtime_admission: &impl SkillRuntimeAdmission,
        registry: &CapabilityRegistry,
        principal_policy: &impl SkillPrincipalPolicy,
    ) -> Result<SkillRuntimeGrant, RuntimeAuthorizationError> {
        self.extension_policy.require_skills(request)?;
        admitted.binding().require_request(server, request)?;
        let manifest = admitted.manifest();
        let lifecycle = lifecycle_repository
            .load(admitted.binding(), manifest.uri.as_str())
            .map_err(|_| RuntimeAuthorizationError::Unavailable)?
            .ok_or(RuntimeAuthorizationError::Disabled)?;
        lifecycle
            .require_enabled(admitted)
            .map_err(|_| RuntimeAuthorizationError::Disabled)?;
        let capabilities = authorize_capabilities(
            registry,
            principal_policy,
            request,
            server,
            &manifest.capabilities,
        )?;
        if capability_keys(&capabilities) != lifecycle.capability_keys {
            return Err(RuntimeAuthorizationError::CapabilityDenied);
        }
        let revocation_revision = runtime_admission
            .current_revocation_revision(&lifecycle)
            .map_err(|_| RuntimeAuthorizationError::AdmissionDenied)?;
        if revocation_revision == 0 {
            return Err(RuntimeAuthorizationError::AdmissionDenied);
        }
        let lease = lifecycle_repository
            .acquire_runtime_lease(&SkillRuntimeLeaseRequest {
                record: &lifecycle,
                revocation_revision,
                capabilities: &capabilities,
            })
            .map_err(map_lease_acquire_error)?;
        if lease.cancellation_token().is_cancelled() {
            return Err(RuntimeAuthorizationError::Fenced);
        }
        Ok(SkillRuntimeGrant {
            binding: lifecycle.binding,
            skill_uri: lifecycle.skill_uri,
            version: lifecycle.version,
            package_digest: lifecycle.package_digest,
            provenance: lifecycle.provenance,
            lifecycle_revision: lifecycle.revision,
            revocation_revision,
            capabilities,
            lease: Some(lease),
        })
    }
}

/// Fixed, redacted runtime authorization failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeAuthorizationError {
    /// The exact extension revision was absent or experimental Skills was not explicitly enabled.
    #[error("Skill runtime extension is disabled")]
    Negotiation,
    /// Tenant, principal, server, installation, package, or provenance binding differed.
    #[error("Skill runtime scope does not match")]
    ScopeMismatch,
    /// The package is absent, stale, disabled, or uninstalled.
    #[error("Skill runtime package is disabled")]
    Disabled,
    /// Authoritative lifecycle state could not be loaded.
    #[error("Skill runtime state unavailable")]
    Unavailable,
    /// Current trust or revocation policy denied the package.
    #[error("Skill runtime admission denied")]
    AdmissionDenied,
    /// Registry revision, availability, exposure, or current principal/server policy denied use.
    #[error("Skill runtime capability denied")]
    CapabilityDenied,
    /// A lifecycle or revocation generation fence cancelled this lease.
    #[error("Skill runtime lease is fenced")]
    Fenced,
}

impl From<NegotiationError> for RuntimeAuthorizationError {
    fn from(_: NegotiationError) -> Self {
        Self::Negotiation
    }
}

impl From<BindingError> for RuntimeAuthorizationError {
    fn from(_: BindingError) -> Self {
        Self::ScopeMismatch
    }
}

impl From<CapabilityAuthorizationError> for RuntimeAuthorizationError {
    fn from(_: CapabilityAuthorizationError) -> Self {
        Self::CapabilityDenied
    }
}

fn capability_keys(capabilities: &[AuthorizedSkillCapability]) -> BTreeSet<CapabilityKey> {
    capabilities
        .iter()
        .map(|capability| capability.key().clone())
        .collect()
}

const fn map_lease_acquire_error(error: RuntimeLeaseAcquireError) -> RuntimeAuthorizationError {
    match error {
        RuntimeLeaseAcquireError::Disabled => RuntimeAuthorizationError::Disabled,
        RuntimeLeaseAcquireError::AdmissionDenied => RuntimeAuthorizationError::AdmissionDenied,
        RuntimeLeaseAcquireError::Fenced => RuntimeAuthorizationError::Fenced,
        RuntimeLeaseAcquireError::Unavailable => RuntimeAuthorizationError::Unavailable,
    }
}

fn require_lifecycle_authorized(
    request: &McpRequestContext,
    policy: &impl SkillLifecycleOperatorPolicy,
    binding: &SkillBinding,
    skill_uri: &str,
    action: LifecycleAction,
) -> Result<(), LifecycleError> {
    if request.canonical().invocation().authorization() != Decision::Allow
        || policy.authorize(request, binding, skill_uri, action) != Decision::Allow
    {
        return Err(LifecycleError::Denied);
    }
    Ok(())
}

fn next_state(
    current: LifecycleState,
    action: LifecycleAction,
) -> Result<LifecycleState, LifecycleError> {
    match (current, action) {
        (LifecycleState::Installed | LifecycleState::Disabled, LifecycleAction::Enable) => {
            Ok(LifecycleState::Enabled)
        }
        (LifecycleState::Enabled, LifecycleAction::Disable) => Ok(LifecycleState::Disabled),
        (
            LifecycleState::Installed | LifecycleState::Enabled | LifecycleState::Disabled,
            LifecycleAction::Uninstall,
        ) => Ok(LifecycleState::Uninstalled),
        _ => Err(LifecycleError::InvalidTransition),
    }
}

fn audit_event(
    previous_state: Option<LifecycleState>,
    next: &SkillLifecycleRecord,
    actor_id: SubjectId,
    action: LifecycleAction,
) -> LifecycleAuditEvent {
    LifecycleAuditEvent {
        extension_id: next.extension_id.clone(),
        extension_revision: next.extension_revision.clone(),
        binding: next.binding.clone(),
        skill_uri: next.skill_uri.clone(),
        version: next.version.clone(),
        package_digest: next.package_digest.clone(),
        provenance: next.provenance.clone(),
        capability_keys: next.capability_keys.clone(),
        actor_id,
        action,
        previous_state,
        state: next.state,
        revision: next.revision,
    }
}

const fn map_commit_error(error: LifecycleCommitError) -> LifecycleError {
    match error {
        LifecycleCommitError::Conflict => LifecycleError::Conflict,
        LifecycleCommitError::AdmissionDenied => LifecycleError::AdmissionDenied,
        LifecycleCommitError::LeasesActive => LifecycleError::LeasesActive,
        LifecycleCommitError::Unavailable => LifecycleError::Unavailable,
    }
}

/// Fail-closed lifecycle error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LifecycleError {
    /// Identity, verification proof, action, or revision was invalid.
    #[error("invalid Skill lifecycle input")]
    InvalidInput,
    /// Canonical authorization or the explicit lifecycle operator policy denied the action.
    #[error("Skill lifecycle action denied")]
    Denied,
    /// The installed Skill is not enabled for runtime discovery or reads.
    #[error("Skill is disabled")]
    Disabled,
    /// Canonical tenant, principal, server, or installation binding differed.
    #[error("Skill lifecycle scope does not match")]
    ScopeMismatch,
    /// The exact extension revision was absent or experimental Skills was disabled.
    #[error("MCP Skills negotiation failed")]
    Negotiation,
    /// Canonical-binding Skill already exists.
    #[error("Skill is already installed")]
    AlreadyInstalled,
    /// Canonical-binding Skill does not exist.
    #[error("Skill is not installed")]
    NotInstalled,
    /// Requested action is illegal for the current state.
    #[error("invalid Skill lifecycle transition")]
    InvalidTransition,
    /// Another actor changed the record first.
    #[error("Skill lifecycle revision conflict")]
    Conflict,
    /// Trust or revocation changed before commit.
    #[error("Skill lifecycle admission denied")]
    AdmissionDenied,
    /// Matching leases were cancelled and fenced but have not released.
    #[error("Skill lifecycle runtime leases are still active")]
    LeasesActive,
    /// Durable lifecycle repository was unavailable.
    #[error("Skill lifecycle repository unavailable")]
    Unavailable,
}

impl From<BindingError> for LifecycleError {
    fn from(_: BindingError) -> Self {
        Self::ScopeMismatch
    }
}

impl From<NegotiationError> for LifecycleError {
    fn from(_: NegotiationError) -> Self {
        Self::Negotiation
    }
}
