//! End-to-end contracts for scoped MCP Apps admission, lifecycle, resources, and messaging.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityRegistry,
    CapabilityRegistryBuilder, ConfirmationEvidence, ConfirmationPolicy, Exposure, HandlerError,
    HandlerInvocation, IdempotencyPolicy, InvocationContext, RuntimeAvailability, TenantMode,
    TraceContext,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_core::RequestId;
use omnius_mcp_apps::*;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
    McpRequestMetadata,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

const SERVER: &str = "server-a";
const INSTALLATION: &str = "installation-a";
const RESOURCE_BYTES: &[u8] = b"<!doctype html><html><body>safe</body></html>";
const CAPABILITY_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/agent-capability.example.yaml");

#[derive(Clone, Copy)]
struct TestVerifier;

impl ManifestSignatureVerifier for TestVerifier {
    fn verify(
        &self,
        key_id: &str,
        algorithm: &str,
        signed_envelope: &[u8],
        signature: &str,
    ) -> Result<(), SignatureVerificationError> {
        if key_id == "publisher-key"
            && algorithm == "Ed25519"
            && signature == sha256_digest(signed_envelope)
        {
            Ok(())
        } else {
            Err(SignatureVerificationError)
        }
    }
}

#[derive(Clone)]
struct TestLifecycleRepository {
    state: Arc<Mutex<TestLifecycleState>>,
}

#[derive(Default)]
struct TestLifecycleState {
    records: Vec<AppLifecycleRecord>,
    replay: BTreeSet<String>,
    active: BTreeMap<String, ActiveAction>,
    next_lease: u64,
}

struct ActiveAction {
    key: AppLifecycleKey,
    lifecycle_revision: u64,
    capability: omnius_agent_capability_registry::CapabilityKey,
    frame_id: String,
    session_id: String,
    message_id: String,
    cancellation: CancellationToken,
}

impl TestLifecycleRepository {
    fn empty() -> Self {
        Self {
            state: Arc::new(Mutex::new(TestLifecycleState::default())),
        }
    }

    fn active_count(&self) -> Result<usize, MessageReplayError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| MessageReplayError)?
            .active
            .len())
    }
}

impl AppLifecycleRepository for TestLifecycleRepository {
    fn load(
        &self,
        key: &AppLifecycleKey,
    ) -> Result<Option<AppLifecycleRecord>, LifecycleRepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| LifecycleRepositoryError)?
            .records
            .iter()
            .find(|record| record.key == *key)
            .cloned())
    }

    fn install(&self, plan: &AppLifecyclePlan) -> Result<(), LifecycleCommitError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LifecycleCommitError::Unavailable)?;
        if plan.expected_revision != 0
            || state
                .records
                .iter()
                .any(|record| record.key == plan.next.key)
        {
            return Err(LifecycleCommitError::Conflict);
        }
        if state
            .records
            .iter()
            .any(|record| record.resource_uri == plan.next.resource_uri)
        {
            return Err(LifecycleCommitError::UriConflict);
        }
        state.records.push(plan.next.clone());
        Ok(())
    }

    fn commit(&self, plan: &AppLifecyclePlan) -> Result<(), LifecycleCommitError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LifecycleCommitError::Unavailable)?;
        let Some(index) = state
            .records
            .iter()
            .position(|current| current.key == plan.next.key)
        else {
            return Err(LifecycleCommitError::Conflict);
        };
        if state.records[index].revision != plan.expected_revision {
            return Err(LifecycleCommitError::Conflict);
        }
        let active_ids = state
            .active
            .iter()
            .filter_map(|(lease_id, active)| {
                (active.key == plan.next.key).then_some(lease_id.clone())
            })
            .collect::<Vec<_>>();
        if !active_ids.is_empty() {
            for lease_id in active_ids {
                if let Some(active) = state.active.get(&lease_id) {
                    active.cancellation.cancel();
                }
            }
            return Err(LifecycleCommitError::LeaseActive);
        }
        state.records[index] = plan.next.clone();
        Ok(())
    }
}

impl AppActionLeaseRepository for TestLifecycleRepository {
    fn claim_action(
        &self,
        claim: &AppActionClaim<'_>,
    ) -> Result<AppActionClaimResult, MessageReplayError> {
        if claim
            .invocation_context()
            .cancellation_token()
            .is_cancelled()
        {
            return Ok(AppActionClaimResult::Fenced);
        }
        let mut state = self.state.lock().map_err(|_| MessageReplayError)?;
        let current = state.records.iter().find(|record| {
            record.key == *claim.key.lifecycle_key
                && record.state == LifecycleState::Enabled
                && record.revision == claim.key.lifecycle_revision
        });
        if current.is_none() {
            return Ok(AppActionClaimResult::Fenced);
        }
        let replay_key = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            claim.key.lifecycle_key.binding().server_id(),
            claim.key.lifecycle_key.binding().installation_id(),
            claim.key.lifecycle_key.resource_id(),
            claim.key.lifecycle_revision,
            claim.key.frame_id,
            claim.key.session_id,
            claim.key.message_id
        );
        if !state.replay.insert(replay_key) {
            return Ok(AppActionClaimResult::Replay);
        }
        state.next_lease = state.next_lease.saturating_add(1);
        let lease_id = format!("lease-{}", state.next_lease);
        state.active.insert(
            lease_id.clone(),
            ActiveAction {
                key: claim.key.lifecycle_key.clone(),
                lifecycle_revision: claim.key.lifecycle_revision,
                capability: claim.capability.clone(),
                frame_id: claim.key.frame_id.to_owned(),
                session_id: claim.key.session_id.to_owned(),
                message_id: claim.key.message_id.to_owned(),
                cancellation: claim.invocation_context().cancellation_token().clone(),
            },
        );
        Ok(AppActionClaimResult::Acquired { lease_id })
    }

    fn finish_action(
        &self,
        lease: &AppActionLease,
        disposition: AppActionLeaseDisposition,
    ) -> Result<AppActionLeaseFinish, MessageReplayError> {
        let mut state = self.state.lock().map_err(|_| MessageReplayError)?;
        let Some(active) = state.active.remove(lease.lease_id()) else {
            return Ok(AppActionLeaseFinish::Fenced);
        };
        if active.key != *lease.lifecycle_key()
            || active.lifecycle_revision != lease.lifecycle_revision()
            || active.capability != *lease.capability()
            || active.frame_id != lease.frame_id()
            || active.session_id != lease.session_id()
            || active.message_id != lease.message_id()
        {
            return Ok(AppActionLeaseFinish::Fenced);
        }
        if disposition == AppActionLeaseDisposition::Abort {
            return Ok(AppActionLeaseFinish::Aborted);
        }
        let current = state.records.iter().find(|record| {
            record.key == *lease.lifecycle_key()
                && record.state == LifecycleState::Enabled
                && record.revision == lease.lifecycle_revision()
        });
        if active.cancellation.is_cancelled() || current.is_none() {
            return Ok(AppActionLeaseFinish::Fenced);
        }
        Ok(AppActionLeaseFinish::Committed)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TestArtifactSource {
    Exact,
    Corrupt,
    Oversized,
    Fenced,
}

#[derive(Clone)]
struct TestArtifactRepository {
    lifecycle: TestLifecycleRepository,
    source: TestArtifactSource,
}

impl UiArtifactRepository for TestArtifactRepository {
    fn read_exact(
        &self,
        locator: &UiArtifactLocator<'_>,
        destination: &mut [u8],
    ) -> Result<UiArtifactRead, ArtifactRepositoryError> {
        assert_eq!(locator.lifecycle_key.binding().server_id(), SERVER);
        assert!(!locator.capability_keys.is_empty());
        assert_eq!(
            locator.expected_size,
            u64::try_from(destination.len()).unwrap_or(u64::MAX)
        );
        assert_eq!(locator.hard_max_size, MAX_UI_RESOURCE_BYTES);
        let mut state = self
            .lifecycle
            .state
            .lock()
            .map_err(|_| ArtifactRepositoryError)?;
        if self.source == TestArtifactSource::Fenced
            && let Some(record) = state
                .records
                .iter_mut()
                .find(|record| record.key == *locator.lifecycle_key)
        {
            record.state = LifecycleState::Disabled;
            record.revision = record.revision.saturating_add(1);
        }
        let current = state
            .records
            .iter()
            .find(|record| record.key == *locator.lifecycle_key);
        if current.is_none_or(|record| {
            record.state != LifecycleState::Enabled || record.revision != locator.lifecycle_revision
        }) {
            return Ok(UiArtifactRead::StaleLifecycle);
        }
        match self.source {
            TestArtifactSource::Oversized => return Ok(UiArtifactRead::SizeMismatch),
            TestArtifactSource::Fenced => return Ok(UiArtifactRead::StaleLifecycle),
            TestArtifactSource::Exact => destination.copy_from_slice(RESOURCE_BYTES),
            TestArtifactSource::Corrupt => destination.fill(b'x'),
        }
        Ok(UiArtifactRead::Complete {
            media_type: APP_HTML_MEDIA_TYPE.to_owned(),
        })
    }
}

#[derive(Clone)]
struct CountingHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CapabilityHandler for CountingHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"ok": true}))
    }
}

struct CancellationDrop {
    cancellation: CancellationToken,
    observed: Arc<AtomicUsize>,
}

impl Drop for CancellationDrop {
    fn drop(&mut self) {
        if self.cancellation.is_cancelled() {
            self.observed.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Clone)]
struct BlockingHandler {
    started: Arc<Notify>,
    cancellation_observed: Arc<AtomicUsize>,
}

#[async_trait]
impl CapabilityHandler for BlockingHandler {
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        let _drop = CancellationDrop {
            cancellation: invocation.context().cancellation_token().clone(),
            observed: Arc::clone(&self.cancellation_observed),
        };
        self.started.notify_one();
        invocation.context().cancellation_token().cancelled().await;
        Ok(json!({"committed": false}))
    }
}

fn capability_document(version: &str) -> Result<CapabilityDocument, Box<dyn Error>> {
    let mut document: CapabilityDocument = serde_yaml::from_str(CAPABILITY_EXAMPLE)?;
    document.id = "apps.records.read".parse()?;
    document.version = version.parse()?;
    document.permissions.clear();
    document.confirmation = ConfirmationPolicy::Never;
    document.idempotency = IdempotencyPolicy::NotApplicable;
    document.tenant_modes = vec![TenantMode::Tenant];
    document.exposures = vec![Exposure::Browser];
    document.input_schema = serde_json::from_value(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["record_id"],
        "properties": {
            "record_id": {"type": "string"}
        }
    }))?;
    document.output_schema = serde_json::from_value(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object"
    }))?;
    document.deprecated = false;
    Ok(document)
}

fn registry(
    version: &str,
    calls: Arc<AtomicUsize>,
) -> Result<
    (
        CapabilityRegistry,
        omnius_agent_capability_registry::CapabilityKey,
    ),
    Box<dyn Error>,
> {
    let document = capability_document(version)?;
    let key = document.key();
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document,
        RuntimeAvailability::Available,
        CountingHandler { calls },
    )?;
    Ok((builder.build(), key))
}
fn blocking_registry(
    handler: BlockingHandler,
) -> Result<
    (
        CapabilityRegistry,
        omnius_agent_capability_registry::CapabilityKey,
    ),
    Box<dyn Error>,
> {
    let document = capability_document("1.0.0")?;
    let key = document.key();
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(document, RuntimeAvailability::Available, handler)?;
    Ok((builder.build(), key))
}

fn exact_extension() -> Result<McpExtension, Box<dyn Error>> {
    Ok(apps_extension()?)
}

fn request(
    tenant_id: TenantId,
    subject_id: SubjectId,
    decision: Decision,
    requested: McpExtension,
    supported: McpExtension,
) -> Result<McpRequestContext, Box<dyn Error>> {
    let principal = Principal::new(
        subject_id,
        PrincipalKind::User,
        Some(tenant_id),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal2,
        vec![Scope::new("apps:invoke")?],
    )?;
    let invocation = InvocationContext::new(
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal,
        Some(tenant_id),
        decision,
        "policy.apps".parse()?,
        BudgetBounds::new(256 * 1024, 256 * 1024, 100)?,
        OffsetDateTime::now_utc() + time::Duration::seconds(30),
        CancellationToken::new(),
    )?;
    let canonical = McpCanonicalContext::new(invocation, TenantMode::Tenant)?;
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("apps-contract-client", "1.0.0")?,
        ["tools".to_owned()],
        [requested],
        None,
    )?;
    Ok(McpRequestContext::new(
        metadata,
        &McpExtensionCatalog::new([supported])?,
        canonical,
    ))
}

fn exact_request(
    tenant_id: TenantId,
    subject_id: SubjectId,
    decision: Decision,
) -> Result<McpRequestContext, Box<dyn Error>> {
    request(
        tenant_id,
        subject_id,
        decision,
        exact_extension()?,
        exact_extension()?,
    )
}

fn client_support() -> ClientAppSupport {
    ClientAppSupport {
        isolated_origin: true,
        host_messaging: true,
    }
}

fn policy() -> HostSecurityPolicy {
    HostSecurityPolicy {
        max_resource_bytes: MAX_UI_RESOURCE_BYTES,
        host_origin: "https://host.example".to_owned(),
        isolation_origins: ["https://apps.example".to_owned()].into_iter().collect(),
        connect_origins: ["https://api.example".to_owned()].into_iter().collect(),
        resource_origins: ["https://cdn.example".to_owned()].into_iter().collect(),
        frame_origins: BTreeSet::default(),
        base_uri_origins: BTreeSet::default(),
        permission_ceiling: BTreeSet::default(),
    }
}

fn signed_manifest(
    request: &McpRequestContext,
    capability: omnius_agent_capability_registry::CapabilityKey,
) -> Result<SignedUiManifest, Box<dyn Error>> {
    let envelope = UiManifestEnvelope::new(
        AppBinding::from_request(request, SERVER, INSTALLATION)?,
        UiManifest {
            extension_version: APPS_EXTENSION_REVISION.to_owned(),
            resource_id: "records-app".to_owned(),
            version: "1.2.3".to_owned(),
            resource: UiResourceMetadata {
                uri: Url::parse(&format!(
                    "ui://{SERVER}/{INSTALLATION}/records-app/1.2.3/{}",
                    sha256_digest(RESOURCE_BYTES)
                ))?,
                media_type: APP_HTML_MEDIA_TYPE.to_owned(),
                byte_len: u64::try_from(RESOURCE_BYTES.len())?,
                digest: sha256_digest(RESOURCE_BYTES),
                isolation_origin: Url::parse("https://apps.example")?,
                csp: CspPolicy {
                    connect_origins: ["https://api.example".to_owned()].into_iter().collect(),
                    resource_origins: ["https://cdn.example".to_owned()].into_iter().collect(),
                    frame_origins: BTreeSet::default(),
                    base_uri_origins: BTreeSet::default(),
                },
                sandbox: SandboxPolicy {
                    tokens: [SandboxToken::AllowScripts, SandboxToken::AllowSameOrigin]
                        .into_iter()
                        .collect(),
                },
                permission_ceiling: BTreeSet::default(),
            },
            messages: vec![MessageContract {
                action: "records.read".to_owned(),
                capability,
                max_payload_bytes: 1_024,
                allowed_fields: ["record_id".to_owned()].into_iter().collect(),
                required_fields: ["record_id".to_owned()].into_iter().collect(),
            }],
            unknown_fields: BTreeMap::default(),
        },
    );
    let signature = sha256_digest(&envelope.canonical_bytes()?);
    Ok(SignedUiManifest {
        key_id: "publisher-key".to_owned(),
        algorithm: "Ed25519".to_owned(),
        signature,
        envelope,
    })
}

fn resign(signed: &mut SignedUiManifest) -> Result<(), ManifestError> {
    signed.signature = sha256_digest(&signed.envelope.canonical_bytes()?);
    Ok(())
}

fn admit_signed(
    registry: &CapabilityRegistry,
    request: &McpRequestContext,
    signed: SignedUiManifest,
) -> Result<AdmittedUiManifest, Box<dyn Error>> {
    Ok(UiManifestAdmission::new(TestVerifier, policy()).admit(
        registry,
        request,
        SERVER,
        INSTALLATION,
        &client_support(),
        signed,
    )?)
}

fn admit(
    registry: &CapabilityRegistry,
    request: &McpRequestContext,
    capability: omnius_agent_capability_registry::CapabilityKey,
) -> Result<AdmittedUiManifest, Box<dyn Error>> {
    admit_signed(registry, request, signed_manifest(request, capability)?)
}

fn enable(
    repository: &TestLifecycleRepository,
    admitted: &AdmittedUiManifest,
    request: &McpRequestContext,
) -> Result<(), Box<dyn Error>> {
    let service = AppLifecycleService::new(repository.clone());
    let installed = service.install(admitted, request, SERVER, INSTALLATION)?;
    service.transition(
        request,
        SERVER,
        INSTALLATION,
        admitted.manifest().resource_id.as_str(),
        installed.revision,
        LifecycleAction::Enable,
    )?;
    Ok(())
}

fn host_context<'a>(
    admitted: &'a AdmittedUiManifest,
    frame_id: &'a str,
    session_id: &'a str,
) -> HostMessageContext<'a> {
    HostMessageContext {
        server_id: SERVER,
        installation_id: INSTALLATION,
        session_id,
        frame_id,
        issued_resource_id: &admitted.manifest().resource_id,
        issued_resource_uri: admitted.manifest().resource.uri.as_str(),
        observed_frame_origin: admitted.manifest().resource.isolation_origin.as_str(),
    }
}

#[test]
fn exact_official_revision_is_required() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let subject = SubjectId::new();
    let wrong = McpExtension::new(
        McpExtensionId::new(APPS_EXTENSION_ID)?,
        McpExtensionRevision::new("2026-01-25")?,
    );
    let context = request(tenant, subject, Decision::Allow, wrong, exact_extension()?)?;
    assert_eq!(
        require_apps(&context),
        Err(AppsNegotiationError::RevisionMismatch)
    );
    Ok(())
}

#[test]
fn admission_rejects_stale_or_unregistered_capability_revision() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, _) = registry("1.0.0", calls)?;
    let stale = capability_document("2.0.0")?.key();
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let result = UiManifestAdmission::new(TestVerifier, policy()).admit(
        &registry,
        &context,
        SERVER,
        INSTALLATION,
        &client_support(),
        signed_manifest(&context, stale)?,
    );

    assert!(matches!(result, Err(ManifestError::RegistryDenied)));
    Ok(())
}

#[test]
fn admission_rejects_uri_collision_and_misleading_segments() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admission = UiManifestAdmission::new(TestVerifier, policy());

    let mut collision = signed_manifest(&context, capability.clone())?;
    collision.envelope.manifest.resource_id = "other-app".to_owned();
    resign(&mut collision)?;
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            collision,
        ),
        Err(ManifestError::InvalidResource)
    );

    let mut misleading = signed_manifest(&context, capability.clone())?;
    misleading.envelope.manifest.resource.uri = Url::parse(&format!(
        "ui://{SERVER}/{INSTALLATION}/records-app/alias/1.2.3/{}",
        sha256_digest(RESOURCE_BYTES)
    ))?;
    resign(&mut misleading)?;
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            misleading,
        ),
        Err(ManifestError::InvalidResource)
    );
    let mut encoded = signed_manifest(&context, capability)?;
    encoded.envelope.manifest.resource.uri = Url::parse(&format!(
        "ui://{SERVER}/{INSTALLATION}/%72ecords-app/1.2.3/{}",
        sha256_digest(RESOURCE_BYTES)
    ))?;
    resign(&mut encoded)?;
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            encoded,
        ),
        Err(ManifestError::InvalidResource)
    );
    Ok(())
}

#[test]
fn admission_rejects_oversized_assets_and_origin_or_csp_expansion() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admission = UiManifestAdmission::new(TestVerifier, policy());

    let mut oversized = signed_manifest(&context, capability.clone())?;
    oversized.envelope.manifest.resource.byte_len = MAX_UI_RESOURCE_BYTES + 1;
    resign(&mut oversized)?;
    assert!(matches!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            oversized,
        ),
        Err(ManifestError::InvalidIntegrity)
    ));

    let mut hostile = signed_manifest(&context, capability)?;
    hostile.envelope.manifest.resource.isolation_origin = Url::parse("https://host.example")?;
    hostile
        .envelope
        .manifest
        .resource
        .csp
        .connect_origins
        .insert("https://attacker.example".to_owned());
    resign(&mut hostile)?;
    assert!(matches!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            hostile,
        ),
        Err(ManifestError::CspDenied)
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table-driven regression keeps every signed-envelope rebind dimension together"
)]
fn signed_envelope_rejects_scope_and_resource_rebinding() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let tenant = TenantId::new();
    let subject = SubjectId::new();
    let context = exact_request(tenant, subject, Decision::Allow)?;
    let signed = signed_manifest(&context, capability)?;
    let signed_bytes = signed.envelope.canonical_bytes()?;
    assert_eq!(
        &signed_bytes[..UI_MANIFEST_SIGNATURE_DOMAIN.len()],
        UI_MANIFEST_SIGNATURE_DOMAIN.as_bytes()
    );
    assert_eq!(signed_bytes[UI_MANIFEST_SIGNATURE_DOMAIN.len()], 0);
    assert_eq!(format!("{signed:?}"), "SignedUiManifest([redacted])");
    assert_eq!(
        format!("{:?}", signed.envelope),
        "UiManifestEnvelope([redacted])"
    );

    let mut first_order = signed.envelope.clone();
    let mut first_object = serde_json::Map::new();
    first_object.insert("a".to_owned(), json!(1));
    first_object.insert("b".to_owned(), json!(2));
    first_order
        .manifest
        .unknown_fields
        .insert("x-canonical".to_owned(), Value::Object(first_object));
    let mut second_order = signed.envelope.clone();
    let mut second_object = serde_json::Map::new();
    second_object.insert("b".to_owned(), json!(2));
    second_object.insert("a".to_owned(), json!(1));
    second_order
        .manifest
        .unknown_fields
        .insert("x-canonical".to_owned(), Value::Object(second_object));
    assert_eq!(
        first_order.canonical_bytes()?,
        second_order.canonical_bytes()?
    );

    let admitted = admit_signed(&registry, &context, signed.clone())?;
    assert_eq!(admitted.manifest_digest(), sha256_digest(&signed_bytes));

    let admission = UiManifestAdmission::new(TestVerifier, policy());
    let other_tenant = exact_request(TenantId::new(), subject, Decision::Allow)?;
    let Err(tenant_error) = admission.admit(
        &registry,
        &other_tenant,
        SERVER,
        INSTALLATION,
        &client_support(),
        signed.clone(),
    ) else {
        panic!("cross-tenant envelope replay must fail");
    };
    assert_eq!(tenant_error, ManifestError::ContextMismatch);
    assert_eq!(tenant_error.to_string(), "MCP App identity scope mismatch");

    let other_principal = exact_request(tenant, SubjectId::new(), Decision::Allow)?;
    assert_eq!(
        admission.admit(
            &registry,
            &other_principal,
            SERVER,
            INSTALLATION,
            &client_support(),
            signed.clone(),
        ),
        Err(ManifestError::ContextMismatch)
    );
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            "server-b",
            INSTALLATION,
            &client_support(),
            signed.clone(),
        ),
        Err(ManifestError::ContextMismatch)
    );
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            "installation-b",
            &client_support(),
            signed.clone(),
        ),
        Err(ManifestError::ContextMismatch)
    );

    let mut rebound_tenant = signed.clone();
    rebound_tenant.envelope.binding =
        AppBinding::from_request(&other_tenant, SERVER, INSTALLATION)?;
    assert_eq!(
        admission.admit(
            &registry,
            &other_tenant,
            SERVER,
            INSTALLATION,
            &client_support(),
            rebound_tenant,
        ),
        Err(ManifestError::InvalidSignature)
    );
    let mut rebound_principal = signed.clone();
    rebound_principal.envelope.binding =
        AppBinding::from_request(&other_principal, SERVER, INSTALLATION)?;
    assert_eq!(
        admission.admit(
            &registry,
            &other_principal,
            SERVER,
            INSTALLATION,
            &client_support(),
            rebound_principal,
        ),
        Err(ManifestError::InvalidSignature)
    );
    let mut rebound_server = signed.clone();
    rebound_server.envelope.binding = AppBinding::from_request(&context, "server-b", INSTALLATION)?;
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            "server-b",
            INSTALLATION,
            &client_support(),
            rebound_server,
        ),
        Err(ManifestError::InvalidSignature)
    );
    let mut rebound_installation = signed.clone();
    rebound_installation.envelope.binding =
        AppBinding::from_request(&context, SERVER, "installation-b")?;
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            "installation-b",
            &client_support(),
            rebound_installation,
        ),
        Err(ManifestError::InvalidSignature)
    );

    let mut rebound_resource_id = signed.clone();
    rebound_resource_id.envelope.manifest.resource_id = "other-app".to_owned();
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            rebound_resource_id,
        ),
        Err(ManifestError::InvalidSignature)
    );
    let mut rebound_resource_uri = signed.clone();
    rebound_resource_uri.envelope.manifest.resource.uri = Url::parse(&format!(
        "ui://{SERVER}/{INSTALLATION}/other-app/1.2.3/{}",
        sha256_digest(RESOURCE_BYTES)
    ))?;
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            rebound_resource_uri,
        ),
        Err(ManifestError::InvalidSignature)
    );

    let mut oversized_key_id = signed.clone();
    oversized_key_id.key_id = "k".repeat(129);
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            oversized_key_id,
        ),
        Err(ManifestError::InvalidSignature)
    );
    let mut oversized_signature = signed;
    oversized_signature.signature = "s".repeat(257);
    assert_eq!(
        admission.admit(
            &registry,
            &context,
            SERVER,
            INSTALLATION,
            &client_support(),
            oversized_signature,
        ),
        Err(ManifestError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn admitted_csp_cannot_be_reused_across_tenant_principal_or_server() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let tenant = TenantId::new();
    let subject = SubjectId::new();
    let context = exact_request(tenant, subject, Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let other_tenant = exact_request(TenantId::new(), subject, Decision::Allow)?;
    let other_principal = exact_request(tenant, SubjectId::new(), Decision::Allow)?;

    assert!(
        admitted
            .content_security_policy(&other_tenant, SERVER, INSTALLATION)
            .is_err()
    );
    assert!(
        admitted
            .content_security_policy(&other_principal, SERVER, INSTALLATION)
            .is_err()
    );
    assert!(
        admitted
            .content_security_policy(&context, "server-b", INSTALLATION)
            .is_err()
    );
    assert!(
        admitted
            .content_security_policy(&context, SERVER, "installation-b")
            .is_err()
    );
    Ok(())
}

#[test]
fn immutable_resource_locator_is_scoped_and_digest_checked() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &context)?;
    let service = UiResourceService::new(
        TestArtifactRepository {
            lifecycle: lifecycle.clone(),
            source: TestArtifactSource::Exact,
        },
        lifecycle.clone(),
    );
    let resource_contents =
        service.read(&admitted, &context, SERVER, INSTALLATION, &client_support())?;
    assert_eq!(
        resource_contents.locator.key().binding(),
        admitted.binding()
    );

    let corrupt = UiResourceService::new(
        TestArtifactRepository {
            lifecycle: lifecycle.clone(),
            source: TestArtifactSource::Corrupt,
        },
        lifecycle,
    );
    assert!(matches!(
        corrupt.read(&admitted, &context, SERVER, INSTALLATION, &client_support(),),
        Err(ResourceError::IntegrityMismatch)
    ));
    Ok(())
}

#[test]
fn oversized_artifact_source_is_rejected_by_bounded_exact_read() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &context)?;
    let service = UiResourceService::new(
        TestArtifactRepository {
            lifecycle: lifecycle.clone(),
            source: TestArtifactSource::Oversized,
        },
        lifecycle,
    );

    assert_eq!(
        service.read(&admitted, &context, SERVER, INSTALLATION, &client_support(),),
        Err(ResourceError::IntegrityMismatch)
    );
    Ok(())
}

#[test]
fn artifact_read_is_fenced_when_lifecycle_advances_at_the_read_boundary()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &context)?;
    let service = UiResourceService::new(
        TestArtifactRepository {
            lifecycle: lifecycle.clone(),
            source: TestArtifactSource::Fenced,
        },
        lifecycle,
    );

    assert_eq!(
        service.read(&admitted, &context, SERVER, INSTALLATION, &client_support(),),
        Err(ResourceError::Disabled)
    );
    Ok(())
}

#[test]
fn disabled_and_deleted_installations_fail_closed() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    let service = AppLifecycleService::new(lifecycle.clone());
    let installed = service.install(&admitted, &context, SERVER, INSTALLATION)?;
    let resource = UiResourceService::new(
        TestArtifactRepository {
            lifecycle: lifecycle.clone(),
            source: TestArtifactSource::Exact,
        },
        lifecycle.clone(),
    );
    assert!(matches!(
        resource.read(&admitted, &context, SERVER, INSTALLATION, &client_support(),),
        Err(ResourceError::Disabled)
    ));
    let enabled = service.transition(
        &context,
        SERVER,
        INSTALLATION,
        &admitted.manifest().resource_id,
        installed.revision,
        LifecycleAction::Enable,
    )?;
    let disabled = service.transition(
        &context,
        SERVER,
        INSTALLATION,
        &admitted.manifest().resource_id,
        enabled.revision,
        LifecycleAction::Disable,
    )?;
    service.transition(
        &context,
        SERVER,
        INSTALLATION,
        &admitted.manifest().resource_id,
        disabled.revision,
        LifecycleAction::Uninstall,
    )?;
    assert!(matches!(
        resource.read(&admitted, &context, SERVER, INSTALLATION, &client_support(),),
        Err(ResourceError::Disabled)
    ));
    Ok(())
}

#[test]
fn lifecycle_install_enforces_resource_uri_uniqueness_transactionally() -> Result<(), Box<dyn Error>>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls)?;
    let first_context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let first = admit(&registry, &first_context, capability.clone())?;
    let second_context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let second = admit(&registry, &second_context, capability)?;
    let repository = TestLifecycleRepository::empty();
    let service = AppLifecycleService::new(repository);
    service.install(&first, &first_context, SERVER, INSTALLATION)?;

    assert_eq!(
        service.install(&second, &second_context, SERVER, INSTALLATION),
        Err(LifecycleError::UriConflict)
    );
    Ok(())
}

#[tokio::test]
async fn post_message_origin_replay_and_scope_attacks_are_denied() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls.clone())?;
    let tenant = TenantId::new();
    let subject = SubjectId::new();
    let context = exact_request(tenant, subject, Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &context)?;
    let service = HostMessageService::new(lifecycle);
    let message = InboundHostMessage {
        message_id: "message-1".to_owned(),
        resource_id: admitted.manifest().resource_id.clone(),
        action: "records.read".to_owned(),
        payload: json!({"record_id": "record-1"}),
    };
    let evidence = || HostInvocationEvidence {
        confirmation: ConfirmationEvidence::NotProvided,
        idempotency_key: None,
    };
    let hostile = HostMessageContext {
        observed_frame_origin: "https://attacker.example",
        ..host_context(&admitted, "frame-1", "session-1")
    };
    assert!(matches!(
        service
            .handle(HostMessageInvocation {
                registry: &registry,
                admitted: &admitted,
                request: &context,
                client: &client_support(),
                host: hostile,
                evidence: evidence(),
                message: &message,
            })
            .await,
        Err(MessageError::InvalidMessage)
    ));

    let valid = host_context(&admitted, "frame-1", "session-1");
    let stale_registry = CapabilityRegistryBuilder::new().build();
    assert!(matches!(
        service
            .handle(HostMessageInvocation {
                registry: &stale_registry,
                admitted: &admitted,
                request: &context,
                client: &client_support(),
                host: valid,
                evidence: evidence(),
                message: &message,
            })
            .await,
        Err(MessageError::StaleCapability)
    ));
    let response = service
        .handle(HostMessageInvocation {
            registry: &registry,
            admitted: &admitted,
            request: &context,
            client: &client_support(),
            host: valid,
            evidence: evidence(),
            message: &message,
        })
        .await?;
    assert_eq!(response.message_id, message.message_id);
    assert!(matches!(
        service
            .handle(HostMessageInvocation {
                registry: &registry,
                admitted: &admitted,
                request: &context,
                client: &client_support(),
                host: valid,
                evidence: evidence(),
                message: &message,
            })
            .await,
        Err(MessageError::Replay)
    ));
    let other_frame_response = service
        .handle(HostMessageInvocation {
            registry: &registry,
            admitted: &admitted,
            request: &context,
            client: &client_support(),
            host: host_context(&admitted, "frame-2", "session-2"),
            evidence: evidence(),
            message: &message,
        })
        .await?;
    assert_eq!(other_frame_response.message_id, message.message_id);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn same_origin_frame_cannot_substitute_another_issued_resource() -> Result<(), Box<dyn Error>>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", Arc::clone(&calls))?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let victim = admit(&registry, &context, capability.clone())?;
    let mut attacker_signed = signed_manifest(&context, capability)?;
    attacker_signed.envelope.manifest.resource_id = "notes-app".to_owned();
    attacker_signed.envelope.manifest.resource.uri = Url::parse(&format!(
        "ui://{SERVER}/{INSTALLATION}/notes-app/1.2.3/{}",
        sha256_digest(RESOURCE_BYTES)
    ))?;
    resign(&mut attacker_signed)?;
    let attacker = admit_signed(&registry, &context, attacker_signed)?;
    assert_eq!(
        attacker.manifest().resource.isolation_origin,
        victim.manifest().resource.isolation_origin
    );
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &victim, &context)?;
    enable(&lifecycle, &attacker, &context)?;
    let result = HostMessageService::new(lifecycle)
        .handle(HostMessageInvocation {
            registry: &registry,
            admitted: &victim,
            request: &context,
            client: &client_support(),
            host: host_context(&attacker, "frame-attacker", "session-attacker"),
            evidence: HostInvocationEvidence {
                confirmation: ConfirmationEvidence::NotProvided,
                idempotency_key: None,
            },
            message: &InboundHostMessage {
                message_id: "message-cross-frame".to_owned(),
                resource_id: victim.manifest().resource_id.clone(),
                action: "records.read".to_owned(),
                payload: json!({"record_id": "record-1"}),
            },
        })
        .await;

    assert_eq!(result, Err(MessageError::InvalidMessage));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn replay_key_rejects_action_and_capability_substitution() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let read_document = capability_document("1.0.0")?;
    let read_capability = read_document.key();
    let mut write_document = capability_document("1.0.0")?;
    write_document.id = "apps.records.write".parse()?;
    let write_capability = write_document.key();
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        read_document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    builder.register(
        write_document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let registry = builder.build();
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let mut signed = signed_manifest(&context, read_capability)?;
    signed.envelope.manifest.messages.push(MessageContract {
        action: "records.write".to_owned(),
        capability: write_capability,
        max_payload_bytes: 1_024,
        allowed_fields: ["record_id".to_owned()].into_iter().collect(),
        required_fields: ["record_id".to_owned()].into_iter().collect(),
    });
    resign(&mut signed)?;
    let admitted = admit_signed(&registry, &context, signed)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &context)?;
    let service = HostMessageService::new(lifecycle);
    let host = host_context(&admitted, "frame-substitution", "session-substitution");
    let evidence = || HostInvocationEvidence {
        confirmation: ConfirmationEvidence::NotProvided,
        idempotency_key: None,
    };
    let first = InboundHostMessage {
        message_id: "message-substitution".to_owned(),
        resource_id: admitted.manifest().resource_id.clone(),
        action: "records.read".to_owned(),
        payload: json!({"record_id": "record-1"}),
    };
    service
        .handle(HostMessageInvocation {
            registry: &registry,
            admitted: &admitted,
            request: &context,
            client: &client_support(),
            host,
            evidence: evidence(),
            message: &first,
        })
        .await?;
    let substituted = InboundHostMessage {
        action: "records.write".to_owned(),
        ..first
    };
    assert_eq!(
        service
            .handle(HostMessageInvocation {
                registry: &registry,
                admitted: &admitted,
                request: &context,
                client: &client_support(),
                host,
                evidence: evidence(),
                message: &substituted,
            })
            .await,
        Err(MessageError::Replay)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_fences_and_cancels_an_in_flight_action_lease() -> Result<(), Box<dyn Error>> {
    let started = Arc::new(Notify::new());
    let cancellation_observed = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = blocking_registry(BlockingHandler {
        started: Arc::clone(&started),
        cancellation_observed: Arc::clone(&cancellation_observed),
    })?;
    let context = exact_request(TenantId::new(), SubjectId::new(), Decision::Allow)?;
    let admitted = admit(&registry, &context, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &context)?;
    let enabled = lifecycle
        .load(&AppLifecycleKey::from_admitted(&admitted))?
        .ok_or("enabled record")?;
    let message = InboundHostMessage {
        message_id: "message-race".to_owned(),
        resource_id: admitted.manifest().resource_id.clone(),
        action: "records.read".to_owned(),
        payload: json!({"record_id": "record-race"}),
    };
    let task = {
        let lifecycle = lifecycle.clone();
        let admitted = admitted.clone();
        let context = context.clone();
        tokio::spawn(async move {
            HostMessageService::new(lifecycle)
                .handle(HostMessageInvocation {
                    registry: &registry,
                    admitted: &admitted,
                    request: &context,
                    client: &client_support(),
                    host: host_context(&admitted, "frame-race", "session-race"),
                    evidence: HostInvocationEvidence {
                        confirmation: ConfirmationEvidence::NotProvided,
                        idempotency_key: None,
                    },
                    message: &message,
                })
                .await
        })
    };
    started.notified().await;
    assert_eq!(lifecycle.active_count()?, 1);

    let lifecycle_service = AppLifecycleService::new(lifecycle.clone());
    assert_eq!(
        lifecycle_service.transition(
            &context,
            SERVER,
            INSTALLATION,
            enabled.key.resource_id(),
            enabled.revision,
            LifecycleAction::Disable,
        ),
        Err(LifecycleError::LeaseActive)
    );
    assert_eq!(task.await?, Err(MessageError::Denied));
    assert_eq!(cancellation_observed.load(Ordering::SeqCst), 1);
    let disabled = lifecycle_service.transition(
        &context,
        SERVER,
        INSTALLATION,
        enabled.key.resource_id(),
        enabled.revision,
        LifecycleAction::Disable,
    )?;
    assert_eq!(disabled.state, LifecycleState::Disabled);
    assert_eq!(lifecycle.active_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn registry_authorization_cannot_be_bypassed_by_manifest_declarations()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (registry, capability) = registry("1.0.0", calls.clone())?;
    let tenant = TenantId::new();
    let subject = SubjectId::new();
    let allowed = exact_request(tenant, subject, Decision::Allow)?;
    let denied = exact_request(
        tenant,
        subject,
        Decision::Deny(DenyReason::InsufficientScope),
    )?;
    let admitted = admit(&registry, &allowed, capability)?;
    let lifecycle = TestLifecycleRepository::empty();
    enable(&lifecycle, &admitted, &allowed)?;
    let service = HostMessageService::new(lifecycle);
    let result = service
        .handle(HostMessageInvocation {
            registry: &registry,
            admitted: &admitted,
            request: &denied,
            client: &client_support(),
            host: host_context(&admitted, "frame-denied", "session-denied"),
            evidence: HostInvocationEvidence {
                confirmation: ConfirmationEvidence::Confirmed,
                idempotency_key: None,
            },
            message: &InboundHostMessage {
                message_id: "message-denied".to_owned(),
                resource_id: admitted.manifest().resource_id.clone(),
                action: "records.read".to_owned(),
                payload: json!({"record_id": "record-1"}),
            },
        })
        .await;

    assert!(matches!(result, Err(MessageError::Denied)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
