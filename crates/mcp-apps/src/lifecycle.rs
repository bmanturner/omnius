use std::collections::BTreeSet;

use omnius_agent_capability_registry::CapabilityKey;
use omnius_auth_core::SubjectId;
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::manifest::{AdmittedUiManifest, AppBinding, is_uri_segment_identifier};
use crate::negotiation::{APPS_EXTENSION_ID, APPS_EXTENSION_REVISION};

/// Durable App lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Installed and default-off.
    Installed,
    /// Explicitly enabled by an authorized operator.
    Enabled,
    /// Explicitly disabled.
    Disabled,
    /// Tombstoned uninstall; retained audit history and artifacts remain governed by policy.
    Uninstalled,
}

/// Exact canonical scope used for every lifecycle repository lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppLifecycleKey {
    binding: AppBinding,
    resource_id: String,
}

impl AppLifecycleKey {
    /// Creates the exact repository key captured during admission.
    #[must_use]
    pub fn from_admitted(admitted: &AdmittedUiManifest) -> Self {
        Self {
            binding: admitted.binding().clone(),
            resource_id: admitted.manifest().resource_id.clone(),
        }
    }

    /// Derives an exact repository key from a fresh canonical request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::InvalidInput`] when `resource_id` is not a bounded URI segment,
    /// or [`LifecycleError::Denied`] when the request cannot establish the exact App binding.
    pub fn from_request(
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
        resource_id: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        let resource_id = resource_id.into();
        if !is_uri_segment_identifier(&resource_id) {
            return Err(LifecycleError::InvalidInput);
        }
        let binding = AppBinding::from_request(context, server_id, installation_id)
            .map_err(|_| LifecycleError::Denied)?;
        Ok(Self {
            binding,
            resource_id,
        })
    }

    /// Returns the canonical identity and host binding.
    #[must_use]
    pub const fn binding(&self) -> &AppBinding {
        &self.binding
    }

    /// Returns the stable App resource identity.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// Authoritative repository record for one installed immutable App version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppLifecycleRecord {
    /// Exact tenant, principal, server, installation, and resource lookup identity.
    pub key: AppLifecycleKey,
    /// Stable official extension identifier.
    pub extension_id: String,
    /// Exact official extension revision used at admission.
    pub extension_revision: String,
    /// Installed immutable App version.
    pub version: String,
    /// Digest of the admitted signed manifest.
    pub manifest_digest: String,
    /// Non-secret signer key identifier.
    pub signer_key_id: String,
    /// Exact registry capability revisions admitted only as execution ceilings.
    pub capability_keys: BTreeSet<CapabilityKey>,
    /// Sole canonical immutable resource URI.
    pub resource_uri: Url,
    /// Immutable resource content digest.
    pub resource_digest: String,
    /// Exact immutable resource byte length.
    pub resource_byte_len: u64,
    /// Current state.
    pub state: LifecycleState,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
}

impl AppLifecycleRecord {
    /// Requires a freshly loaded enabled record matching all identity and provenance fields.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::Disabled`] unless the request binding and every enabled
    /// lifecycle provenance field exactly match the admitted manifest.
    pub fn require_enabled(
        &self,
        admitted: &AdmittedUiManifest,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
    ) -> Result<(), LifecycleError> {
        admitted
            .binding()
            .require_request(context, server_id, installation_id)
            .map_err(|_| LifecycleError::Disabled)?;
        let manifest = admitted.manifest();
        if self.state != LifecycleState::Enabled
            || self.key != AppLifecycleKey::from_admitted(admitted)
            || self.extension_id != APPS_EXTENSION_ID
            || self.extension_revision != APPS_EXTENSION_REVISION
            || self.version != manifest.version
            || self.resource_uri != manifest.resource.uri
            || self.resource_digest != manifest.resource.digest
            || self.resource_byte_len != manifest.resource.byte_len
            || self.manifest_digest != admitted.manifest_digest()
            || self.signer_key_id != admitted.signer_key_id()
            || &self.capability_keys != admitted.capability_keys()
        {
            return Err(LifecycleError::Disabled);
        }
        Ok(())
    }
}

/// Operator lifecycle action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    /// Install an admitted version in the disabled state.
    Install,
    /// Enable an installed or disabled version.
    Enable,
    /// Disable an enabled version.
    Disable,
    /// Tombstone and uninstall a disabled version.
    Uninstall,
}

/// Fixed-field audit event that cannot carry manifest content or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAuditEvent {
    /// Exact lifecycle lookup identity.
    pub key: AppLifecycleKey,
    /// Exact official extension revision.
    pub extension_revision: String,
    /// Immutable App version.
    pub version: String,
    /// Integrity-only manifest digest.
    pub manifest_digest: String,
    /// Exact registry capability revisions retained for audit correlation.
    pub capability_keys: BTreeSet<CapabilityKey>,
    /// Canonical authenticated operator identity.
    pub actor_id: SubjectId,
    /// Applied transition.
    pub action: LifecycleAction,
    /// Previous state, absent only for install.
    pub previous_state: Option<LifecycleState>,
    /// Resulting state.
    pub state: LifecycleState,
    /// Resulting repository revision.
    pub revision: u64,
}

/// Atomic repository change plus its mandatory audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppLifecyclePlan {
    /// Revision expected by compare-and-swap; zero means the record must not exist.
    pub expected_revision: u64,
    /// Complete next authoritative record.
    pub next: AppLifecycleRecord,
    /// Audit event committed in the same durable transaction.
    pub audit: LifecycleAuditEvent,
}

/// Durable authoritative lifecycle, URI uniqueness, lease fencing, and audit boundary.
pub trait AppLifecycleRepository {
    /// Loads the current record under the complete canonical scope, if any.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleRepositoryError`] when authoritative lifecycle state cannot be read.
    fn load(
        &self,
        key: &AppLifecycleKey,
    ) -> Result<Option<AppLifecycleRecord>, LifecycleRepositoryError>;

    /// Atomically requires an absent key and URI, stores the installation, and appends its audit.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleCommitError`] when the absent-key or URI requirement fails, or when
    /// the record and audit event cannot be committed atomically.
    fn install(&self, plan: &AppLifecyclePlan) -> Result<(), LifecycleCommitError>;

    /// Atomically compares revision, fences active action leases, stores, and appends the audit.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleCommitError`] when the expected revision or active-lease fence fails,
    /// or when the record and audit event cannot be committed atomically.
    fn commit(&self, plan: &AppLifecyclePlan) -> Result<(), LifecycleCommitError>;
}

/// Redacted repository read error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("App lifecycle repository read failed")]
pub struct LifecycleRepositoryError;

/// Atomic lifecycle commit failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LifecycleCommitError {
    /// Expected revision no longer matches authoritative state.
    #[error("App lifecycle revision conflict")]
    Conflict,
    /// The canonical resource URI already belongs to an installation.
    #[error("App resource URI is already installed")]
    UriConflict,
    /// An in-flight action lease was cancelled and must release before the transition can retry.
    #[error("App lifecycle transition is fenced by an active action")]
    LeaseActive,
    /// Durable state or audit append failed.
    #[error("App lifecycle commit failed")]
    Unavailable,
}

/// Lifecycle coordinator producing explicit authorized and auditable transitions.
pub struct AppLifecycleService<R> {
    repository: R,
}

impl<R> AppLifecycleService<R>
where
    R: AppLifecycleRepository,
{
    /// Creates a lifecycle service around the deployment repository.
    #[must_use]
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Installs an admitted App default-off in the same fresh canonical scope.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] when authorization, scope, repository availability, uniqueness,
    /// or the atomic installation commit prevents installation.
    pub fn install(
        &self,
        admitted: &AdmittedUiManifest,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
    ) -> Result<AppLifecycleRecord, LifecycleError> {
        require_authorized(context)?;
        admitted
            .binding()
            .require_request(context, server_id, installation_id)
            .map_err(|_| LifecycleError::Denied)?;
        let key = AppLifecycleKey::from_admitted(admitted);
        let current = self
            .repository
            .load(&key)
            .map_err(|_| LifecycleError::Unavailable)?;
        if current.is_some() {
            return Err(LifecycleError::AlreadyInstalled);
        }
        let next = AppLifecycleRecord {
            key,
            extension_id: APPS_EXTENSION_ID.to_owned(),
            extension_revision: APPS_EXTENSION_REVISION.to_owned(),
            version: admitted.manifest().version.clone(),
            manifest_digest: admitted.manifest_digest().to_owned(),
            signer_key_id: admitted.signer_key_id().to_owned(),
            capability_keys: admitted.capability_keys().clone(),
            resource_uri: admitted.manifest().resource.uri.clone(),
            resource_digest: admitted.manifest().resource.digest.clone(),
            resource_byte_len: admitted.manifest().resource.byte_len,
            state: LifecycleState::Installed,
            revision: 1,
        };
        let plan = AppLifecyclePlan {
            expected_revision: 0,
            audit: audit_event(None, &next, context, LifecycleAction::Install),
            next,
        };
        self.repository.install(&plan).map_err(map_commit_error)?;
        Ok(plan.next)
    }

    /// Applies an enable, disable, or uninstall command under the exact canonical scope.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] when authorization, scope, current state, expected revision,
    /// repository availability, lease fencing, or the requested state transition prevents commit.
    pub fn transition(
        &self,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
        resource_id: &str,
        expected_revision: u64,
        action: LifecycleAction,
    ) -> Result<AppLifecycleRecord, LifecycleError> {
        require_authorized(context)?;
        if expected_revision == 0 || action == LifecycleAction::Install {
            return Err(LifecycleError::InvalidTransition);
        }
        let key = AppLifecycleKey::from_request(context, server_id, installation_id, resource_id)?;
        let current = self
            .repository
            .load(&key)
            .map_err(|_| LifecycleError::Unavailable)?
            .ok_or(LifecycleError::NotInstalled)?;
        if current.key != key
            || current.extension_id != APPS_EXTENSION_ID
            || current.extension_revision != APPS_EXTENSION_REVISION
        {
            return Err(LifecycleError::Denied);
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
        let plan = AppLifecyclePlan {
            expected_revision,
            audit: audit_event(Some(current.state), &next, context, action),
            next,
        };
        self.repository.commit(&plan).map_err(map_commit_error)?;
        Ok(plan.next)
    }
}

/// Fail-closed lifecycle error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LifecycleError {
    /// Identifier, digest, action, or revision was invalid.
    #[error("invalid App lifecycle input")]
    InvalidInput,
    /// Canonical authorization, negotiation, or identity scope denied the operation.
    #[error("App lifecycle action denied")]
    Denied,
    /// The App already exists and cannot be overwritten by install.
    #[error("App is already installed")]
    AlreadyInstalled,
    /// The App has not been installed in this exact scope.
    #[error("App is not installed")]
    NotInstalled,
    /// The canonical immutable resource URI is already installed.
    #[error("App resource URI is already installed")]
    UriConflict,
    /// The installed App is not enabled or no longer matches admitted provenance.
    #[error("App is disabled")]
    Disabled,
    /// State and requested action form an illegal transition.
    #[error("invalid App lifecycle transition")]
    InvalidTransition,
    /// Another actor changed the record first.
    #[error("App lifecycle revision conflict")]
    Conflict,
    /// A cancelled in-flight action must release its lease before retrying the transition.
    #[error("App lifecycle transition is fenced by an active action")]
    LeaseActive,
    /// The authoritative lifecycle repository was unavailable.
    #[error("App lifecycle repository unavailable")]
    Unavailable,
}

fn require_authorized(context: &McpRequestContext) -> Result<(), LifecycleError> {
    if context.canonical().invocation().authorization() != Decision::Allow {
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
        (LifecycleState::Installed | LifecycleState::Disabled, LifecycleAction::Uninstall) => {
            Ok(LifecycleState::Uninstalled)
        }
        _ => Err(LifecycleError::InvalidTransition),
    }
}

fn audit_event(
    previous_state: Option<LifecycleState>,
    next: &AppLifecycleRecord,
    context: &McpRequestContext,
    action: LifecycleAction,
) -> LifecycleAuditEvent {
    LifecycleAuditEvent {
        key: next.key.clone(),
        extension_revision: next.extension_revision.clone(),
        version: next.version.clone(),
        manifest_digest: next.manifest_digest.clone(),
        capability_keys: next.capability_keys.clone(),
        actor_id: context.canonical().invocation().principal().subject_id,
        action,
        previous_state,
        state: next.state,
        revision: next.revision,
    }
}

const fn map_commit_error(error: LifecycleCommitError) -> LifecycleError {
    match error {
        LifecycleCommitError::Conflict => LifecycleError::Conflict,
        LifecycleCommitError::Unavailable => LifecycleError::Unavailable,
        LifecycleCommitError::UriConflict => LifecycleError::UriConflict,
        LifecycleCommitError::LeaseActive => LifecycleError::LeaseActive,
    }
}
