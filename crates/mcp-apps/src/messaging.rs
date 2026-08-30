use std::collections::BTreeSet;

use omnius_agent_capability_registry::{
    CapabilityInvocation, CapabilityKey, CapabilityRegistry, ConfirmationEvidence, Exposure,
    IdempotencyKey, InvocationContext,
};
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

use crate::lifecycle::{AppLifecycleKey, AppLifecycleRepository};
use crate::manifest::{
    AdmittedUiManifest, ClientAppSupport, MessageContract, is_identifier, is_sensitive_name,
    is_uri_segment_identifier, validate_client_support,
};

/// Maximum inbound or outbound host-message envelope size.
pub const MAX_HOST_MESSAGE_BYTES: usize = 128 * 1024;

/// Strict inbound message accepted from an isolated App frame.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundHostMessage {
    /// Correlation and replay-protection identifier.
    pub message_id: String,
    /// Resource identity asserted by the frame.
    pub resource_id: String,
    /// Manifest-declared action.
    pub action: String,
    /// Contract-validated action payload.
    pub payload: Value,
}

impl std::fmt::Debug for InboundHostMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InboundHostMessage([redacted])")
    }
}

/// Trusted host facts supplied by the MCP adapter, never by App JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostMessageContext<'a> {
    /// MCP server identity.
    pub server_id: &'a str,
    /// App installation identity.
    pub installation_id: &'a str,
    /// Host-created App session identity.
    pub session_id: &'a str,
    /// Opaque host frame handle resolved from the message event source.
    pub frame_id: &'a str,
    /// Resource identity issued to that exact frame.
    pub issued_resource_id: &'a str,
    /// Exact immutable `ui://` resource URI issued to that exact frame.
    pub issued_resource_uri: &'a str,
    /// Dedicated frame origin observed by the trusted host adapter.
    pub observed_frame_origin: &'a str,
}

/// Ordinary confirmation and idempotency evidence supplied by the trusted host adapter.
///
/// App JSON cannot populate these fields. The canonical registry still validates the evidence
/// against the registry-owned capability document before handler dispatch.
pub struct HostInvocationEvidence {
    /// Confirmation evidence established outside the untrusted frame.
    pub confirmation: ConfirmationEvidence,
    /// Optional validated idempotency key established outside the untrusted frame.
    pub idempotency_key: Option<IdempotencyKey>,
}

/// Complete trusted authority-boundary input for one untrusted App message.
pub struct HostMessageInvocation<'a> {
    /// Canonical capability registry used for document lookup and dispatch.
    pub registry: &'a CapabilityRegistry,
    /// Previously admitted manifest that bounds the App's actions.
    pub admitted: &'a AdmittedUiManifest,
    /// Fresh canonical MCP request context.
    pub request: &'a McpRequestContext,
    /// Client isolation and host-messaging support.
    pub client: &'a ClientAppSupport,
    /// Host-observed frame, session, installation, and resource facts.
    pub host: HostMessageContext<'a>,
    /// Host-established confirmation and idempotency evidence.
    pub evidence: HostInvocationEvidence,
    /// Untrusted inbound frame message.
    pub message: &'a InboundHostMessage,
}

/// Replay identity deliberately excludes the declared action and capability.
pub struct MessageReplayKey<'a> {
    /// Exact tenant, principal, server, installation, and resource identity.
    pub lifecycle_key: &'a AppLifecycleKey,
    /// Enabled lifecycle revision that must remain current throughout dispatch.
    pub lifecycle_revision: u64,
    /// Opaque host frame handle resolved from the message event source.
    pub frame_id: &'a str,
    /// Host-created App session identity.
    pub session_id: &'a str,
    /// Correlation identifier.
    pub message_id: &'a str,
}

/// Atomic replay claim carrying the selected capability and cooperative cancellation.
pub struct AppActionClaim<'a> {
    /// Exact replay and lifecycle-generation key.
    pub key: MessageReplayKey<'a>,
    /// Exact registry capability revision retained by the active action lease.
    pub capability: &'a CapabilityKey,
    invocation_context: InvocationContext,
}

impl<'a> AppActionClaim<'a> {
    fn new(
        key: MessageReplayKey<'a>,
        capability: &'a CapabilityKey,
        invocation_context: InvocationContext,
    ) -> Self {
        Self {
            key,
            capability,
            invocation_context,
        }
    }

    /// Returns the leased context whose cancellation token fences lifecycle transitions.
    #[must_use]
    pub const fn invocation_context(&self) -> &InvocationContext {
        &self.invocation_context
    }
}

/// Typed atomic claim result; only `Acquired` permits capability dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppActionClaimResult {
    /// Replay and exact enabled generation were claimed under this opaque lease identity.
    Acquired {
        /// Repository-minted opaque action lease identifier.
        lease_id: String,
    },
    /// The replay key was already claimed.
    Replay,
    /// The exact lifecycle generation is no longer enabled.
    Fenced,
}

/// Opaque active lease retained through handler execution and final result commit.
pub struct AppActionLease {
    lease_id: String,
    lifecycle_key: AppLifecycleKey,
    lifecycle_revision: u64,
    capability: CapabilityKey,
    frame_id: String,
    session_id: String,
    message_id: String,
    invocation_context: InvocationContext,
}

impl AppActionLease {
    fn from_claim(claim: &AppActionClaim<'_>, lease_id: String) -> Result<Self, MessageError> {
        if !is_identifier(&lease_id) {
            return Err(MessageError::ReplayUnavailable);
        }
        Ok(Self {
            lease_id,
            lifecycle_key: claim.key.lifecycle_key.clone(),
            lifecycle_revision: claim.key.lifecycle_revision,
            capability: claim.capability.clone(),
            frame_id: claim.key.frame_id.to_owned(),
            session_id: claim.key.session_id.to_owned(),
            message_id: claim.key.message_id.to_owned(),
            invocation_context: claim.invocation_context.clone(),
        })
    }

    /// Returns the repository-issued opaque lease identity.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Returns the complete App lifecycle key.
    #[must_use]
    pub const fn lifecycle_key(&self) -> &AppLifecycleKey {
        &self.lifecycle_key
    }

    /// Returns the exact enabled generation fenced by this lease.
    #[must_use]
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the exact capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the opaque host frame handle.
    #[must_use]
    pub fn frame_id(&self) -> &str {
        &self.frame_id
    }

    /// Returns the host-created App session identity.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the replay-protected correlation identifier.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns the exact canonical context shared with the capability handler.
    #[must_use]
    pub const fn invocation_context(&self) -> &InvocationContext {
        &self.invocation_context
    }

    fn cancel(&self) {
        self.invocation_context.cancellation_token().cancel();
    }
}

impl std::fmt::Debug for AppActionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AppActionLease([redacted])")
    }
}

/// Whether final lease release commits or aborts externally observable action completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppActionLeaseDisposition {
    /// Final lifecycle fence passed and the sanitized result may become observable.
    Commit,
    /// Handler failure, cancellation, invalid output, or dropped future releases without commit.
    Abort,
}

/// Typed final lease/fence result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppActionLeaseFinish {
    /// The exact enabled generation remained current and completion committed.
    Committed,
    /// The lease was released without committing action completion.
    Aborted,
    /// Lifecycle generation changed or cancellation fenced commit.
    Fenced,
}

/// Replay and lifecycle lease boundary coordinated with the lifecycle repository.
pub trait AppActionLeaseRepository {
    /// Atomically verifies a live cancellation token and exact enabled revision, claims replay,
    /// captures the selected capability for the active lease, and registers the token for
    /// lifecycle fencing.
    ///
    /// # Errors
    ///
    /// Returns [`MessageReplayError`] when the atomic lifecycle fence and replay claim cannot be
    /// completed.
    fn claim_action(
        &self,
        claim: &AppActionClaim<'_>,
    ) -> Result<AppActionClaimResult, MessageReplayError>;

    /// Atomically rechecks the lifecycle fence and releases the lease with the requested outcome.
    ///
    /// Lifecycle disable/uninstall commits using the paired [`AppLifecycleRepository`] must cancel
    /// matching active tokens and cannot advance their revision until every lease is released.
    ///
    /// # Errors
    ///
    /// Returns [`MessageReplayError`] when the final lifecycle recheck and lease release cannot be
    /// completed atomically.
    fn finish_action(
        &self,
        lease: &AppActionLease,
        disposition: AppActionLeaseDisposition,
    ) -> Result<AppActionLeaseFinish, MessageReplayError>;
}

/// Redacted replay or action-lease repository error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("host message action lease repository failed")]
pub struct MessageReplayError;

/// Correlated host response with no bearer, header, or capability-handle fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostMessageResponse {
    /// Original message correlation identifier.
    pub message_id: String,
    /// Sanitized public capability result.
    pub result: Value,
}

impl std::fmt::Debug for HostMessageResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostMessageResponse([redacted])")
    }
}

/// Validates and dispatches messages under one atomic replay and lifecycle lease boundary.
pub struct HostMessageService<R> {
    repository: R,
}

impl<R> HostMessageService<R>
where
    R: AppLifecycleRepository + AppActionLeaseRepository,
{
    /// Creates a host message service around one coordinated lifecycle and action repository.
    #[must_use]
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Handles one App message through `CapabilityRegistry::invoke` with fresh request context.
    ///
    /// # Errors
    ///
    /// Returns [`MessageError`] when any negotiation, identity, frame, lifecycle, replay,
    /// capability, payload, cancellation, dispatch, or result-sanitization check fails.
    pub async fn handle(
        &self,
        input: HostMessageInvocation<'_>,
    ) -> Result<HostMessageResponse, MessageError> {
        let HostMessageInvocation {
            registry,
            admitted,
            request,
            client,
            host,
            evidence,
            message,
        } = input;
        validate_client_support(client).map_err(|_| MessageError::Disabled)?;
        admitted
            .binding()
            .require_request(request, host.server_id, host.installation_id)
            .map_err(|_| MessageError::Disabled)?;
        if request.canonical().invocation().authorization() != Decision::Allow {
            return Err(MessageError::Denied);
        }
        let (observed_frame_origin, issued_resource_uri) = validate_host_context(host)?;
        let key = AppLifecycleKey::from_admitted(admitted);
        let lifecycle = self
            .repository
            .load(&key)
            .map_err(|_| MessageError::Disabled)?
            .ok_or(MessageError::Disabled)?;
        lifecycle
            .require_enabled(admitted, request, host.server_id, host.installation_id)
            .map_err(|_| MessageError::Disabled)?;
        require_host_frame_binding(
            admitted,
            &lifecycle,
            host,
            &observed_frame_origin,
            &issued_resource_uri,
        )?;
        let contract = validate_message(admitted, message)?;
        let document = registry
            .document(&contract.capability)
            .ok_or(MessageError::StaleCapability)?;
        if document.deprecated
            || document
                .exposures
                .binary_search(&Exposure::Browser)
                .is_err()
        {
            return Err(MessageError::StaleCapability);
        }
        let invocation_context = leased_invocation_context(request)?;
        let claim = AppActionClaim::new(
            MessageReplayKey {
                lifecycle_key: &key,
                lifecycle_revision: lifecycle.revision,
                frame_id: host.frame_id,
                session_id: host.session_id,
                message_id: &message.message_id,
            },
            &contract.capability,
            invocation_context,
        );
        let lease_id = match self
            .repository
            .claim_action(&claim)
            .map_err(|_| MessageError::ReplayUnavailable)?
        {
            AppActionClaimResult::Acquired { lease_id } => lease_id,
            AppActionClaimResult::Replay => return Err(MessageError::Replay),
            AppActionClaimResult::Fenced => return Err(MessageError::Disabled),
        };
        let lease = AppActionLease::from_claim(&claim, lease_id)?;
        let mut active = ActiveActionLease::new(&self.repository, lease);
        let invocation_context = active.lease().invocation_context().clone();
        let invocation = CapabilityInvocation::new(
            contract.capability.clone(),
            invocation_context,
            request.canonical().tenant_mode(),
            message.payload.clone(),
            evidence.confirmation,
            evidence.idempotency_key,
        );
        let result = registry
            .invoke(Exposure::Browser, invocation)
            .await
            .map_err(|_| MessageError::Denied)?;
        if serialized_len(result.output()).is_none_or(|size| size > MAX_HOST_MESSAGE_BYTES)
            || contains_sensitive_material(result.output())
        {
            return Err(MessageError::CredentialLeak);
        }
        active.commit()?;
        Ok(HostMessageResponse {
            message_id: message.message_id.clone(),
            result: result.output().clone(),
        })
    }
}
struct ActiveActionLease<'a, R>
where
    R: AppActionLeaseRepository,
{
    repository: &'a R,
    lease: Option<AppActionLease>,
}

impl<'a, R> ActiveActionLease<'a, R>
where
    R: AppActionLeaseRepository,
{
    fn new(repository: &'a R, lease: AppActionLease) -> Self {
        Self {
            repository,
            lease: Some(lease),
        }
    }

    fn lease(&self) -> &AppActionLease {
        self.lease
            .as_ref()
            .unwrap_or_else(|| unreachable!("active action lease is present until finalization"))
    }

    fn commit(&mut self) -> Result<(), MessageError> {
        match self
            .repository
            .finish_action(self.lease(), AppActionLeaseDisposition::Commit)
            .map_err(|_| MessageError::ReplayUnavailable)?
        {
            AppActionLeaseFinish::Committed => {
                self.lease.take();
                Ok(())
            }
            AppActionLeaseFinish::Fenced => Err(MessageError::Disabled),
            AppActionLeaseFinish::Aborted => Err(MessageError::ReplayUnavailable),
        }
    }
}

impl<R> Drop for ActiveActionLease<'_, R>
where
    R: AppActionLeaseRepository,
{
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.cancel();
            let _ = self
                .repository
                .finish_action(&lease, AppActionLeaseDisposition::Abort);
        }
    }
}

fn leased_invocation_context(
    request: &McpRequestContext,
) -> Result<InvocationContext, MessageError> {
    let context = request.canonical().invocation();
    InvocationContext::new(
        context.request_id(),
        context.trace_context().clone(),
        context.principal().clone(),
        context.tenant_id(),
        context.authorization(),
        context.data_policy().clone(),
        context.budget(),
        context.deadline(),
        context.cancellation_token().child_token(),
    )
    .map_err(|_| MessageError::Denied)
}

/// Host-message rejection with no attacker-controlled content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MessageError {
    /// Trusted host facts were malformed.
    #[error("invalid host message context")]
    InvalidContext,
    /// Negotiation, identity, client support, or lifecycle state denied messaging.
    #[error("App host messaging is disabled")]
    Disabled,
    /// Message envelope, origin, resource, action, or payload violated its signed ceiling.
    #[error("invalid host message")]
    InvalidMessage,
    /// The exact registry capability revision is absent, deprecated, or not browser exposed.
    #[error("App capability revision is stale")]
    StaleCapability,
    /// Atomic replay protection was unavailable.
    #[error("host message replay protection unavailable")]
    ReplayUnavailable,
    /// The message ID was already used in this complete App scope.
    #[error("replayed host message")]
    Replay,
    /// Canonical registry authorization, consent, policy, or execution denied the request.
    #[error("host action denied")]
    Denied,
    /// Input or output could expose credential or host capability material.
    #[error("host message contains forbidden credential material")]
    CredentialLeak,
}

fn validate_host_context(context: HostMessageContext<'_>) -> Result<(Url, Url), MessageError> {
    if [
        context.server_id,
        context.installation_id,
        context.session_id,
        context.frame_id,
    ]
    .iter()
    .any(|value| !is_identifier(value))
        || !is_uri_segment_identifier(context.issued_resource_id)
    {
        return Err(MessageError::InvalidContext);
    }
    let observed_origin =
        Url::parse(context.observed_frame_origin).map_err(|_| MessageError::InvalidContext)?;
    if observed_origin.scheme() != "https"
        || observed_origin.host_str().is_none()
        || !observed_origin.username().is_empty()
        || observed_origin.password().is_some()
        || observed_origin.path() != "/"
        || observed_origin.query().is_some()
        || observed_origin.fragment().is_some()
    {
        return Err(MessageError::InvalidContext);
    }
    let issued_resource =
        Url::parse(context.issued_resource_uri).map_err(|_| MessageError::InvalidContext)?;
    if issued_resource.scheme() != "ui"
        || issued_resource.host_str().is_none()
        || !issued_resource.username().is_empty()
        || issued_resource.password().is_some()
        || issued_resource.query().is_some()
        || issued_resource.fragment().is_some()
        || issued_resource.as_str() != context.issued_resource_uri
    {
        return Err(MessageError::InvalidContext);
    }
    Ok((observed_origin, issued_resource))
}

fn require_host_frame_binding(
    admitted: &AdmittedUiManifest,
    lifecycle: &crate::lifecycle::AppLifecycleRecord,
    context: HostMessageContext<'_>,
    observed_frame_origin: &Url,
    issued_resource_uri: &Url,
) -> Result<(), MessageError> {
    let manifest = admitted.manifest();
    if context.issued_resource_id != manifest.resource_id
        || context.issued_resource_id != lifecycle.key.resource_id()
        || context.issued_resource_uri != manifest.resource.uri.as_str()
        || context.issued_resource_uri != lifecycle.resource_uri.as_str()
        || issued_resource_uri != &manifest.resource.uri
        || issued_resource_uri != &lifecycle.resource_uri
        || observed_frame_origin != &manifest.resource.isolation_origin
    {
        return Err(MessageError::InvalidMessage);
    }
    Ok(())
}

fn validate_message<'a>(
    admitted: &'a AdmittedUiManifest,
    message: &InboundHostMessage,
) -> Result<&'a MessageContract, MessageError> {
    let manifest = admitted.manifest();
    if !is_identifier(&message.message_id)
        || message.resource_id != manifest.resource_id
        || serialized_len(message).is_none_or(|size| size > MAX_HOST_MESSAGE_BYTES)
    {
        return Err(MessageError::InvalidMessage);
    }
    let contract = manifest
        .messages
        .iter()
        .find(|contract| contract.action == message.action)
        .ok_or(MessageError::InvalidMessage)?;
    validate_payload(contract, &message.payload)?;
    Ok(contract)
}

fn validate_payload(contract: &MessageContract, payload: &Value) -> Result<(), MessageError> {
    let Value::Object(fields) = payload else {
        return Err(MessageError::InvalidMessage);
    };
    if serialized_len(payload).is_none_or(|size| size > contract.max_payload_bytes)
        || contains_sensitive_material(payload)
    {
        return Err(MessageError::CredentialLeak);
    }
    let field_names = fields.keys().cloned().collect::<BTreeSet<_>>();
    if !field_names.is_subset(&contract.allowed_fields)
        || !contract.required_fields.is_subset(&field_names)
    {
        return Err(MessageError::InvalidMessage);
    }
    Ok(())
}

fn contains_sensitive_material(value: &Value) -> bool {
    match value {
        Value::Object(fields) => object_contains_sensitive_material(fields),
        Value::Array(values) => values.iter().any(contains_sensitive_material),
        Value::String(text) => {
            let lowercase = text.to_ascii_lowercase();
            lowercase.contains("authorization: bearer ")
                || lowercase.contains("mcp-host-capability")
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn object_contains_sensitive_material(fields: &Map<String, Value>) -> bool {
    fields
        .iter()
        .any(|(key, value)| is_sensitive_name(key) || contains_sensitive_material(value))
}

fn serialized_len(value: &impl Serialize) -> Option<usize> {
    serde_json::to_vec(value).ok().map(|encoded| encoded.len())
}
