//! Contracts for signed, replay-safe MRTR elicitation and retry lifecycles.
#![expect(
    clippy::expect_used,
    reason = "contract fixtures use invariant-specific failure messages"
)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_agent_capability_registry::{
    BudgetBounds, ConfirmationEvidence, InvocationContext, TenantMode, TraceContext,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use omnius_mcp_elicitation::wire::{WireError, parse_input_responses, to_rmcp_input_required};
use omnius_mcp_elicitation::{
    BeginRequest, ClaimResult, ClientElicitationCapabilities, DeclineBehavior, ElicitationPlan,
    FieldPlan, FormElicitationPlan, FormProtection, InputRequestKey, InvocationBinding,
    InvocationContinuation, InvocationDisposition, InvocationError, LifecycleError,
    MRTR_EXTENSION_ID, MRTR_EXTENSION_REVISION, MrtrAuditEvent, MrtrAuditKind, MrtrConfig,
    MrtrMethod, MrtrService, MrtrStateRepository, NormalInvocationPort, NormalInvocationRequest,
    OriginalInvocation, PendingMrtrState, PlanError, PlannedElicitation, ReplacementReason,
    RepositoryError, ResumeOutcome, ResumeRequest, Sensitivity, StateClaim, TerminalStatus,
    UrlElicitationPlan,
};
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
    McpRequestMetadata,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SIGNING_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const OTHER_SIGNING_KEY: &[u8] = b"abcdef0123456789abcdef0123456789";

type TestService = MrtrService<MemoryRepository, MemoryInvoker>;

#[derive(Clone, Debug)]
enum StoredStatus {
    Pending,
    Claimed,
    Terminal(TerminalStatus),
    Replaced(ReplacementReason),
}

#[derive(Clone, Debug)]
struct StoredEntry {
    record: PendingMrtrState,
    status: StoredStatus,
}

#[derive(Default)]
struct MemoryLedger {
    entries: HashMap<Uuid, StoredEntry>,
    events: Vec<MrtrAuditEvent>,
    atomic_calls: Vec<&'static str>,
}

#[derive(Clone, Default)]
struct MemoryRepository {
    ledger: Arc<Mutex<MemoryLedger>>,
}

impl MemoryRepository {
    fn pending_count(&self) -> usize {
        self.ledger.lock().map_or(0, |ledger| {
            ledger
                .entries
                .values()
                .filter(|entry| matches!(entry.status, StoredStatus::Pending))
                .count()
        })
    }

    fn snapshot(&self) -> String {
        self.ledger.lock().map_or_else(
            |_| "[LOCK ERROR]".to_owned(),
            |ledger| format!("{:?}", ledger.entries),
        )
    }

    fn terminal_statuses(&self) -> Vec<TerminalStatus> {
        self.ledger.lock().map_or_else(
            |_| Vec::new(),
            |ledger| {
                ledger
                    .entries
                    .values()
                    .filter_map(|entry| match entry.status {
                        StoredStatus::Terminal(status) => Some(status),
                        StoredStatus::Pending
                        | StoredStatus::Claimed
                        | StoredStatus::Replaced(_) => None,
                    })
                    .collect()
            },
        )
    }

    fn replacement_reasons(&self) -> Vec<ReplacementReason> {
        self.ledger.lock().map_or_else(
            |_| Vec::new(),
            |ledger| {
                ledger
                    .entries
                    .values()
                    .filter_map(|entry| match entry.status {
                        StoredStatus::Replaced(reason) => Some(reason),
                        StoredStatus::Pending
                        | StoredStatus::Claimed
                        | StoredStatus::Terminal(_) => None,
                    })
                    .collect()
            },
        )
    }

    fn atomic_calls(&self) -> Vec<&'static str> {
        self.ledger
            .lock()
            .map_or_else(|_| Vec::new(), |ledger| ledger.atomic_calls.clone())
    }

    fn event_kinds(&self) -> Vec<MrtrAuditKind> {
        self.ledger.lock().map_or_else(
            |_| Vec::new(),
            |ledger| ledger.events.iter().map(|event| event.kind).collect(),
        )
    }

    fn audit_snapshot(&self) -> String {
        self.ledger.lock().map_or_else(
            |_| "[LOCK ERROR]".to_owned(),
            |ledger| format!("{:?}", ledger.events),
        )
    }
}

#[async_trait]
impl MrtrStateRepository for MemoryRepository {
    async fn create_pending(
        &self,
        state: &PendingMrtrState,
        event: MrtrAuditEvent,
    ) -> Result<PendingMrtrState, RepositoryError> {
        let mut ledger = self.ledger.lock().map_err(|_| RepositoryError)?;
        if ledger.entries.contains_key(&state.state_id) {
            return Err(RepositoryError);
        }
        ledger.entries.insert(
            state.state_id,
            StoredEntry {
                record: state.clone(),
                status: StoredStatus::Pending,
            },
        );
        ledger.events.push(event);
        ledger.atomic_calls.push("create+audit");
        Ok(state.clone())
    }

    async fn claim_pending(
        &self,
        claim: StateClaim,
        claimed_event: MrtrAuditEvent,
        rejected_event: MrtrAuditEvent,
    ) -> Result<ClaimResult, RepositoryError> {
        let mut ledger = self.ledger.lock().map_err(|_| RepositoryError)?;
        let claimed = ledger.entries.get_mut(&claim.state_id).and_then(|entry| {
            if matches!(entry.status, StoredStatus::Pending)
                && entry.record.binding == claim.expected_binding
                && claim.now < entry.record.expires_at
            {
                entry.status = StoredStatus::Claimed;
                Some(entry.record.clone())
            } else {
                None
            }
        });
        let result = if let Some(state) = claimed {
            ledger.events.push(claimed_event);
            ClaimResult::Claimed(Box::new(state))
        } else {
            ledger.events.push(rejected_event);
            ClaimResult::Rejected
        };
        ledger.atomic_calls.push("claim+audit");
        Ok(result)
    }

    async fn replace_claimed(
        &self,
        claimed_state_id: Uuid,
        fresh: &PendingMrtrState,
        reason: ReplacementReason,
        event: MrtrAuditEvent,
    ) -> Result<PendingMrtrState, RepositoryError> {
        let mut ledger = self.ledger.lock().map_err(|_| RepositoryError)?;
        if ledger.entries.contains_key(&fresh.state_id) {
            return Err(RepositoryError);
        }
        let entry = ledger
            .entries
            .get_mut(&claimed_state_id)
            .ok_or(RepositoryError)?;
        if !matches!(entry.status, StoredStatus::Claimed) {
            return Err(RepositoryError);
        }
        entry.status = StoredStatus::Replaced(reason);
        ledger.entries.insert(
            fresh.state_id,
            StoredEntry {
                record: fresh.clone(),
                status: StoredStatus::Pending,
            },
        );
        ledger.events.push(event);
        ledger.atomic_calls.push("replace+audit");
        Ok(fresh.clone())
    }

    async fn finish_claimed(
        &self,
        claimed_state_id: Uuid,
        status: TerminalStatus,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError> {
        let mut ledger = self.ledger.lock().map_err(|_| RepositoryError)?;
        let entry = ledger
            .entries
            .get_mut(&claimed_state_id)
            .ok_or(RepositoryError)?;
        if !matches!(entry.status, StoredStatus::Claimed) {
            return Err(RepositoryError);
        }
        entry.status = StoredStatus::Terminal(status);
        ledger.events.push(event);
        ledger.atomic_calls.push("finish+audit");
        Ok(())
    }

    async fn record_claimed(
        &self,
        claimed_state_id: Uuid,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError> {
        let mut ledger = self.ledger.lock().map_err(|_| RepositoryError)?;
        if !ledger
            .entries
            .get(&claimed_state_id)
            .is_some_and(|entry| matches!(entry.status, StoredStatus::Claimed))
        {
            return Err(RepositoryError);
        }
        ledger.events.push(event);
        ledger.atomic_calls.push("claimed-event");
        Ok(())
    }

    async fn record_untrusted_rejection(
        &self,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError> {
        let mut ledger = self.ledger.lock().map_err(|_| RepositoryError)?;
        ledger.events.push(event);
        ledger.atomic_calls.push("untrusted-event");
        Ok(())
    }
}

#[derive(Clone, Default)]
struct MemoryInvoker {
    calls: Arc<Mutex<Vec<NormalInvocationRequest>>>,
    outcomes: Arc<Mutex<VecDeque<InvocationDisposition<String>>>>,
}

impl MemoryInvoker {
    fn with_outcomes(outcomes: Vec<InvocationDisposition<String>>) -> Self {
        Self {
            calls: Arc::default(),
            outcomes: Arc::new(Mutex::new(outcomes.into())),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().map_or(0, |calls| calls.len())
    }

    fn take_calls(&self) -> Vec<NormalInvocationRequest> {
        self.calls
            .lock()
            .map_or_else(|_| Vec::new(), |mut calls| std::mem::take(&mut *calls))
    }
}

#[async_trait]
impl NormalInvocationPort for MemoryInvoker {
    type Output = String;

    async fn invoke(
        &self,
        request: NormalInvocationRequest,
    ) -> Result<InvocationDisposition<Self::Output>, InvocationError> {
        self.calls
            .lock()
            .map_err(|_| InvocationError)?
            .push(request);
        Ok(self
            .outcomes
            .lock()
            .map_err(|_| InvocationError)?
            .pop_front()
            .unwrap_or_else(|| InvocationDisposition::Complete("complete".to_owned())))
    }
}

fn enabled_config() -> MrtrConfig {
    MrtrConfig {
        enabled: true,
        ..MrtrConfig::default()
    }
}

fn extension(revision: &str) -> McpExtension {
    McpExtension::new(
        McpExtensionId::new(MRTR_EXTENSION_ID).expect("extension ID should be valid"),
        McpExtensionRevision::new(revision).expect("extension revision should be valid"),
    )
}

fn request_context(revision: &str) -> McpRequestContext {
    request_context_for_identity(
        revision,
        0x0189_0f2a_0000_7000_8000_0000_0000_0001,
        0x0189_0f2a_0000_7000_8000_0000_0000_0002,
    )
}

fn request_context_for_identity(revision: &str, subject: u128, tenant: u128) -> McpRequestContext {
    let requested = extension(revision);
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("elicitation-test", "1.0.0")
            .expect("client identity should be valid"),
        ["elicitation".to_owned()],
        [requested],
        None,
    )
    .expect("request metadata should be valid");
    let catalog = McpExtensionCatalog::new([extension(MRTR_EXTENSION_REVISION)])
        .expect("extension catalog should be valid");
    let tenant_id =
        TenantId::from_uuid(Uuid::from_u128(tenant)).expect("tenant ID should be valid");
    let principal = Principal::new(
        SubjectId::from_uuid(Uuid::from_u128(subject)).expect("subject ID should be valid"),
        PrincipalKind::ServiceAccount,
        Some(tenant_id),
        AuthMethod::ApiKey,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        vec![Scope::new("mcp:invoke").expect("scope should be valid")],
    )
    .expect("principal should be valid");
    let invocation = InvocationContext::new(
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .expect("trace parent should be valid"),
            None,
        ),
        principal,
        Some(tenant_id),
        Decision::Allow,
        "policy.mcp-elicitation"
            .parse()
            .expect("data policy should be valid"),
        BudgetBounds::new(1024 * 1024, 1024 * 1024, 100).expect("budget should be valid"),
        OffsetDateTime::now_utc() + time::Duration::minutes(5),
        CancellationToken::new(),
    )
    .expect("invocation context should be valid");
    let canonical = McpCanonicalContext::new(invocation, TenantMode::Tenant)
        .expect("canonical context should be valid");
    McpRequestContext::new(metadata, &catalog, canonical)
}

fn binding(method: MrtrMethod) -> InvocationBinding {
    InvocationBinding::new(method, "summary.publish", "revision-11")
}

fn invocation(method: MrtrMethod) -> OriginalInvocation {
    OriginalInvocation::new(
        binding(method),
        json!({"approved": false, "note": "", "marker": "original-secret"}),
        Some("ordinary-idempotency-key".to_owned()),
    )
}

fn approval_plan(max_rounds: u16, decline: DeclineBehavior) -> ElicitationPlan {
    let field = FieldPlan::try_new("approved", "/approved", Sensitivity::Public)
        .expect("approval field should be valid");
    let form = FormElicitationPlan::try_new(
        "Approve publishing the generated summary?",
        json!({
            "type": "object",
            "required": ["approved"],
            "properties": {"approved": {"type": "boolean"}}
        }),
        vec![field],
        FormProtection::Ordinary,
    )
    .expect("approval form should be valid");
    ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("publish_approval").expect("key should be valid"),
            PlannedElicitation::Form(form),
        )],
        max_rounds,
        decline,
    )
    .expect("approval plan should be valid")
}

fn note_plan(max_rounds: u16) -> ElicitationPlan {
    let field = FieldPlan::try_new("note", "/note", Sensitivity::Public)
        .expect("note field should be valid");
    let form = FormElicitationPlan::try_new(
        "Provide a short note",
        json!({
            "type": "object",
            "required": ["note"],
            "properties": {"note": {"type": "string", "maxLength": 100}}
        }),
        vec![field],
        FormProtection::Ordinary,
    )
    .expect("note form should be valid");
    ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("note").expect("key should be valid"),
            PlannedElicitation::Form(form),
        )],
        max_rounds,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("note plan should be valid")
}

fn url_plan(max_rounds: u16, sensitivity: Sensitivity) -> ElicitationPlan {
    let url = UrlElicitationPlan::try_new(
        "Complete secure credential authorization",
        "https://auth.example.test/elicitation/provider",
        "provider-auth-7",
        sensitivity,
    )
    .expect("URL plan should be valid");
    ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("provider_authorization").expect("key should be valid"),
            PlannedElicitation::Url(url),
        )],
        max_rounds,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("URL plan should be valid")
}

fn test_service(repository: MemoryRepository, invoker: MemoryInvoker) -> TestService {
    MrtrService::try_new(repository, invoker, SIGNING_KEY, enabled_config())
        .expect("test service configuration should be valid")
}

async fn begin_approval(
    service: &TestService,
    method: MrtrMethod,
    max_rounds: u16,
    decline: DeclineBehavior,
) -> omnius_mcp_elicitation::ElicitationChallenge {
    service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(true),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(method),
            plan: approval_plan(max_rounds, decline),
        })
        .await
        .expect("begin should issue a challenge")
}

fn response(key: &str, value: Value) -> BTreeMap<String, Value> {
    BTreeMap::from([(key.to_owned(), value)])
}

fn resume_request(
    challenge: &omnius_mcp_elicitation::ElicitationChallenge,
    invocation: OriginalInvocation,
    input_responses: BTreeMap<String, Value>,
) -> ResumeRequest {
    ResumeRequest {
        context: request_context(MRTR_EXTENSION_REVISION),
        client_capabilities: ClientElicitationCapabilities::form(false),
        confirmation_evidence: ConfirmationEvidence::NotProvided,
        invocation,
        request_state: challenge.request_state.expose_for_wire().to_owned(),
        input_responses,
    }
}

#[tokio::test]
async fn default_configuration_keeps_extension_disabled() {
    let repository = MemoryRepository::default();
    let service = MrtrService::try_new(
        repository.clone(),
        MemoryInvoker::default(),
        SIGNING_KEY,
        MrtrConfig::default(),
    )
    .expect("default configuration should be structurally valid");
    let result = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: approval_plan(2, DeclineBehavior::CompleteDeclined),
        })
        .await;

    assert!(matches!(result, Err(LifecycleError::Disabled)) && repository.pending_count() == 0);
}

#[tokio::test]
async fn exact_mrtr_extension_allows_only_typed_tool_prompt_and_resource_methods() {
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), MemoryInvoker::default());
    for method in [
        MrtrMethod::ToolCall,
        MrtrMethod::PromptGet,
        MrtrMethod::ResourceRead,
    ] {
        begin_approval(&service, method, 2, DeclineBehavior::CompleteDeclined).await;
    }

    assert_eq!(repository.pending_count(), 3);
}

#[tokio::test]
async fn exact_extension_revision_mismatches_never_create_state() {
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), MemoryInvoker::default());
    for revision in ["2026-07-27", "2026-07-29", "2027-01-01"] {
        let result = service
            .begin(BeginRequest {
                context: request_context(revision),
                client_capabilities: ClientElicitationCapabilities::form(false),
                confirmation_evidence: ConfirmationEvidence::NotProvided,
                invocation: invocation(MrtrMethod::ToolCall),
                plan: approval_plan(2, DeclineBehavior::CompleteDeclined),
            })
            .await;

        assert!(matches!(
            result,
            Err(LifecycleError::ExtensionNotNegotiated)
        ));
    }
    assert_eq!(repository.pending_count(), 0);
}
#[tokio::test]
async fn retry_rechecks_the_exact_extension_revision_before_claiming_state() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let result = service
        .resume(ResumeRequest {
            context: request_context("2026-07-29"),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            request_state: challenge.request_state.expose_for_wire().to_owned(),
            input_responses: response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        })
        .await;

    assert!(
        matches!(result, Err(LifecycleError::ExtensionNotNegotiated))
            && repository.pending_count() == 1
            && invoker.call_count() == 0
    );
}

#[tokio::test]
async fn form_mode_must_be_advertised_before_state_creation() {
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), MemoryInvoker::default());
    let result = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::url(),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: approval_plan(2, DeclineBehavior::CompleteDeclined),
        })
        .await;

    assert!(
        matches!(result, Err(LifecycleError::UnsupportedMode)) && repository.pending_count() == 0
    );
}

#[tokio::test]
async fn url_mode_must_be_advertised_before_state_creation() {
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), MemoryInvoker::default());
    let result = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: url_plan(2, Sensitivity::Credential),
        })
        .await;

    assert!(
        matches!(result, Err(LifecycleError::UnsupportedMode)) && repository.pending_count() == 0
    );
}

#[tokio::test]
async fn input_required_wire_shape_matches_the_normative_fixture() {
    let service = test_service(MemoryRepository::default(), MemoryInvoker::default());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let wire = to_rmcp_input_required(&challenge).expect("challenge should map to rmcp");
    let mut actual = serde_json::to_value(wire).expect("wire result should serialize");
    actual["requestState"] = Value::String("opaque-aead-protected-expiring-state".to_owned());
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../specs/examples/llm-mcp-suite/mcp-input-required.example.json"
    ))
    .expect("normative fixture should parse");

    assert_eq!(actual, fixture["result"]);
}

#[tokio::test]
async fn signed_payload_contains_only_version_and_state_id() {
    let service = test_service(MemoryRepository::default(), MemoryInvoker::default());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let body = challenge
        .request_state
        .expose_for_wire()
        .split('.')
        .nth(1)
        .expect("signed state should have a body");
    let decoded = URL_SAFE_NO_PAD
        .decode(body)
        .expect("signed state body should be base64url");
    let payload: Value = serde_json::from_slice(&decoded[8..]).expect("payload should be JSON");
    let keys = payload
        .as_object()
        .expect("payload should be an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();

    assert_eq!(keys, vec!["stateId".to_owned(), "v".to_owned()]);
}

#[tokio::test]
async fn forged_request_state_is_rejected_without_invocation() {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let mut forged = challenge.request_state.expose_for_wire().to_owned();
    forged.push('x');
    let result = service
        .resume(ResumeRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            request_state: forged,
            input_responses: response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        })
        .await;

    assert!(matches!(result, Err(LifecycleError::StateRejected)) && invoker.call_count() == 0);
}

#[tokio::test]
async fn malformed_and_oversized_request_state_is_rejected_without_invocation() {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    for request_state in ["not-a-signed-state".to_owned(), "x".repeat(513)] {
        let result = service
            .resume(ResumeRequest {
                context: request_context(MRTR_EXTENSION_REVISION),
                client_capabilities: ClientElicitationCapabilities::form(false),
                confirmation_evidence: ConfirmationEvidence::NotProvided,
                invocation: invocation(MrtrMethod::ToolCall),
                request_state,
                input_responses: BTreeMap::new(),
            })
            .await;
        assert!(matches!(result, Err(LifecycleError::StateRejected)));
    }

    assert_eq!(invoker.call_count(), 0);
}

#[tokio::test]
async fn state_signed_by_another_key_is_rejected() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let issuer = test_service(repository.clone(), invoker.clone());
    let verifier = MrtrService::try_new(
        repository,
        invoker.clone(),
        OTHER_SIGNING_KEY,
        enabled_config(),
    )
    .expect("second key should be valid");
    let challenge = begin_approval(
        &issuer,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let result = verifier
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        ))
        .await;

    assert!(matches!(result, Err(LifecycleError::StateRejected)) && invoker.call_count() == 0);
}

#[tokio::test]
async fn expired_state_is_rejected_without_invocation() {
    let invoker = MemoryInvoker::default();
    let service = MrtrService::try_new(
        MemoryRepository::default(),
        invoker.clone(),
        SIGNING_KEY,
        MrtrConfig {
            enabled: true,
            request_state_ttl: Duration::from_millis(1),
            max_argument_bytes: 1024 * 1024,
        },
    )
    .expect("short finite TTL should be valid");
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let result = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        ))
        .await;

    assert!(matches!(result, Err(LifecycleError::StateRejected)) && invoker.call_count() == 0);
}

async fn assert_binding_change_rejected(
    mut changed: OriginalInvocation,
    context: McpRequestContext,
) {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    if changed.idempotency_key().is_none() {
        changed = OriginalInvocation::new(
            changed.binding().clone(),
            changed.arguments().clone(),
            Some("ordinary-idempotency-key".to_owned()),
        );
    }
    let result = service
        .resume(ResumeRequest {
            context,
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: changed,
            request_state: challenge.request_state.expose_for_wire().to_owned(),
            input_responses: response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        })
        .await;
    assert!(matches!(result, Err(LifecycleError::StateRejected)) && invoker.call_count() == 0);
}

#[tokio::test]
async fn principal_change_rejects_state() {
    assert_binding_change_rejected(
        invocation(MrtrMethod::ToolCall),
        request_context_for_identity(
            MRTR_EXTENSION_REVISION,
            0x0189_0f2a_0000_7000_8000_0000_0000_0003,
            0x0189_0f2a_0000_7000_8000_0000_0000_0002,
        ),
    )
    .await;
}

#[tokio::test]
async fn tenant_change_rejects_state() {
    assert_binding_change_rejected(
        invocation(MrtrMethod::ToolCall),
        request_context_for_identity(
            MRTR_EXTENSION_REVISION,
            0x0189_0f2a_0000_7000_8000_0000_0000_0001,
            0x0189_0f2a_0000_7000_8000_0000_0000_0004,
        ),
    )
    .await;
}

#[tokio::test]
async fn method_change_rejects_state() {
    assert_binding_change_rejected(
        OriginalInvocation::new(
            binding(MrtrMethod::PromptGet),
            invocation(MrtrMethod::ToolCall).arguments().clone(),
            None,
        ),
        request_context(MRTR_EXTENSION_REVISION),
    )
    .await;
}

#[tokio::test]
async fn capability_revision_change_rejects_state() {
    assert_binding_change_rejected(
        OriginalInvocation::new(
            InvocationBinding::new(MrtrMethod::ToolCall, "summary.publish", "revision-12"),
            invocation(MrtrMethod::ToolCall).arguments().clone(),
            None,
        ),
        request_context(MRTR_EXTENSION_REVISION),
    )
    .await;
}

#[tokio::test]
async fn original_argument_change_rejects_state() {
    assert_binding_change_rejected(
        OriginalInvocation::new(
            binding(MrtrMethod::ToolCall),
            json!({"approved": true, "note": "changed", "marker": "original-secret"}),
            None,
        ),
        request_context(MRTR_EXTENSION_REVISION),
    )
    .await;
}

#[tokio::test]
async fn idempotency_key_add_remove_and_change_reject_state() {
    for (initial_key, retry_key) in [
        (Some("initial-key"), Some("changed-key")),
        (Some("initial-key"), None),
        (None, Some("added-key")),
    ] {
        let repository = MemoryRepository::default();
        let invoker = MemoryInvoker::default();
        let service = test_service(repository, invoker.clone());
        let original_arguments =
            json!({"approved": false, "note": "", "marker": "original-secret"});
        let challenge = service
            .begin(BeginRequest {
                context: request_context(MRTR_EXTENSION_REVISION),
                client_capabilities: ClientElicitationCapabilities::form(false),
                confirmation_evidence: ConfirmationEvidence::NotProvided,
                invocation: OriginalInvocation::new(
                    binding(MrtrMethod::ToolCall),
                    original_arguments.clone(),
                    initial_key.map(str::to_owned),
                ),
                plan: approval_plan(2, DeclineBehavior::CompleteDeclined),
            })
            .await
            .expect("initial state should be issued");
        let result = service
            .resume(ResumeRequest {
                context: request_context(MRTR_EXTENSION_REVISION),
                client_capabilities: ClientElicitationCapabilities::form(false),
                confirmation_evidence: ConfirmationEvidence::NotProvided,
                invocation: OriginalInvocation::new(
                    binding(MrtrMethod::ToolCall),
                    original_arguments,
                    retry_key.map(str::to_owned),
                ),
                request_state: challenge.request_state.expose_for_wire().to_owned(),
                input_responses: response(
                    "publish_approval",
                    json!({"action": "accept", "content": {"approved": true}}),
                ),
            })
            .await;
        assert!(matches!(result, Err(LifecycleError::StateRejected)));
        assert_eq!(invoker.call_count(), 0);
    }
}

#[tokio::test]
async fn object_member_reordering_preserves_the_arguments_binding() {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let initial_arguments: Value =
        serde_json::from_str(r#"{"marker":"original-secret","note":"","approved":false}"#)
            .expect("initial arguments should be valid");
    let challenge = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: OriginalInvocation::new(
                binding(MrtrMethod::ToolCall),
                initial_arguments,
                Some("ordinary-idempotency-key".to_owned()),
            ),
            plan: approval_plan(2, DeclineBehavior::CompleteDeclined),
        })
        .await
        .expect("begin should issue a challenge");
    let reordered_arguments: Value =
        serde_json::from_str(r#"{"approved":false,"marker":"original-secret","note":""}"#)
            .expect("reordered arguments should be valid");
    let result = service
        .resume(ResumeRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: OriginalInvocation::new(
                binding(MrtrMethod::ToolCall),
                reordered_arguments,
                Some("ordinary-idempotency-key".to_owned()),
            ),
            request_state: challenge.request_state.expose_for_wire().to_owned(),
            input_responses: response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        })
        .await;

    assert!(matches!(result, Ok(ResumeOutcome::Complete(_))) && invoker.call_count() == 1);
}

#[tokio::test]
async fn completed_state_cannot_be_replayed() {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let accepted = response(
        "publish_approval",
        json!({"action": "accept", "content": {"approved": true}}),
    );
    let first = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            accepted.clone(),
        ))
        .await;
    let replay = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            accepted,
        ))
        .await;

    assert!(
        matches!(first, Ok(ResumeOutcome::Complete(_)))
            && matches!(replay, Err(LifecycleError::StateRejected))
            && invoker.call_count() == 1
    );
}

#[tokio::test]
async fn concurrent_claim_invokes_exactly_once() {
    let invoker = MemoryInvoker::default();
    let service = Arc::new(test_service(MemoryRepository::default(), invoker.clone()));
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let make_request = || {
        resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        )
    };
    let first_service = Arc::clone(&service);
    let second_service = Arc::clone(&service);
    let (first, second) = tokio::join!(
        first_service.resume(make_request()),
        second_service.resume(make_request())
    );
    let complete_count = usize::from(matches!(&first, Ok(ResumeOutcome::Complete(_))))
        + usize::from(matches!(&second, Ok(ResumeOutcome::Complete(_))));
    let rejection_count = usize::from(matches!(&first, Err(LifecycleError::StateRejected)))
        + usize::from(matches!(&second, Err(LifecycleError::StateRejected)));

    assert_eq!(
        (complete_count, rejection_count, invoker.call_count()),
        (1, 1, 1)
    );
}

#[tokio::test]
async fn invalid_response_at_round_ceiling_is_terminal() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        1,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let result = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": "yes"}}),
            ),
        ))
        .await;

    assert!(
        matches!(result, Ok(ResumeOutcome::Exhausted))
            && repository.pending_count() == 0
            && repository.terminal_statuses() == vec![TerminalStatus::Exhausted]
            && invoker.call_count() == 0
    );
}

#[tokio::test]
async fn response_key_shape_schema_and_action_negatives_get_fresh_bounded_state() {
    let invalid_responses = vec![
        BTreeMap::new(),
        BTreeMap::from([
            (
                "publish_approval".to_owned(),
                json!({"action": "accept", "content": {"approved": true}}),
            ),
            ("unexpected".to_owned(), json!({"action": "cancel"})),
        ]),
        response(
            "publish_approval",
            json!({"method": "sampling/createMessage", "params": {}}),
        ),
        response("publish_approval", json!({"action": "accept"})),
        response(
            "publish_approval",
            json!({"action": "accept", "content": {"approved": "yes"}}),
        ),
        response(
            "publish_approval",
            json!({"action": "accept", "content": {"approved": true, "extra": true}}),
        ),
        response("publish_approval", json!({"action": "later"})),
        response(
            "publish_approval",
            json!({"action": "decline", "content": {}}),
        ),
        response(
            "publish_approval",
            json!({"action": "cancel", "content": {}}),
        ),
    ];

    for invalid in invalid_responses {
        let repository = MemoryRepository::default();
        let invoker = MemoryInvoker::default();
        let service = test_service(repository.clone(), invoker.clone());
        let challenge = begin_approval(
            &service,
            MrtrMethod::ToolCall,
            2,
            DeclineBehavior::CompleteDeclined,
        )
        .await;
        let result = service
            .resume(resume_request(
                &challenge,
                invocation(MrtrMethod::ToolCall),
                invalid,
            ))
            .await;
        assert!(
            matches!(result, Ok(ResumeOutcome::InputRequired(_)))
                && repository.pending_count() == 1
                && repository.replacement_reasons() == vec![ReplacementReason::InvalidResponse]
                && invoker.call_count() == 0
        );
    }
}

#[test]
fn duplicate_response_keys_are_rejected_before_map_conversion() {
    let raw = br#"{
        "publish_approval":{"action":"accept","content":{"approved":true}},
        "publish_approval":{"action":"cancel"}
    }"#;

    assert!(parse_input_responses(raw).is_err());
}

#[test]
fn form_plan_rejects_a_lossy_rmcp_schema_before_state_issuance() {
    let field = FieldPlan::try_new("approved", "/approved", Sensitivity::Public)
        .expect("field should be valid");
    let result = FormElicitationPlan::try_new(
        "Approve?",
        json!({
            "type": "object",
            "properties": {"approved": {"type": "boolean"}},
            "required": ["approved"],
            "additionalProperties": false
        }),
        vec![field],
        FormProtection::Ordinary,
    );

    assert!(matches!(result, Err(PlanError::LossySchema)));
}

#[test]
fn invalid_form_schema_is_rejected_during_plan_construction() {
    let field = FieldPlan::try_new("approved", "/approved", Sensitivity::Public)
        .expect("field should be valid");
    let result = FormElicitationPlan::try_new(
        "Approve?",
        json!({"type": "array", "items": {"type": "boolean"}}),
        vec![field],
        FormProtection::Ordinary,
    );

    assert!(matches!(result, Err(PlanError::InvalidSchema)));
}

#[test]
fn invalid_request_key_is_rejected() {
    assert!(matches!(
        InputRequestKey::try_new("contains whitespace"),
        Err(PlanError::InvalidRequestKey)
    ));
}

#[tokio::test]
async fn accepted_form_is_validated_mapped_and_propagates_canonical_context() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let resume_context = request_context(MRTR_EXTENSION_REVISION);
    let expected_request_id = resume_context.canonical().invocation().request_id();
    let expected_deadline = resume_context.canonical().invocation().deadline();
    let result = service
        .resume(ResumeRequest {
            context: resume_context.clone(),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            request_state: challenge.request_state.expose_for_wire().to_owned(),
            input_responses: response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        })
        .await;
    resume_context
        .canonical()
        .invocation()
        .cancellation_token()
        .cancel();
    let calls = invoker.take_calls();

    assert!(
        matches!(result, Ok(ResumeOutcome::Complete(_)))
            && calls.len() == 1
            && calls[0].arguments["approved"] == json!(true)
            && calls[0].idempotency_key.as_deref() == Some("ordinary-idempotency-key")
            && calls[0].mrtr.round == 1
            && calls[0].mrtr.state_id != Uuid::nil()
            && calls[0].context.canonical().invocation().request_id() == expected_request_id
            && calls[0].context.canonical().invocation().deadline() == expected_deadline
            && calls[0]
                .context
                .canonical()
                .invocation()
                .cancellation_token()
                .is_cancelled()
            && repository.atomic_calls()
                == vec![
                    "create+audit",
                    "claim+audit",
                    "claimed-event",
                    "finish+audit"
                ]
            && repository.event_kinds()
                == vec![
                    MrtrAuditKind::Issued,
                    MrtrAuditKind::Claimed,
                    MrtrAuditKind::Accepted,
                    MrtrAuditKind::Completed
                ]
    );
}

#[tokio::test]
async fn decline_completes_normally_without_invocation_when_policy_says_stop() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let result = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response("publish_approval", json!({"action": "decline"})),
        ))
        .await;

    assert!(
        matches!(result, Ok(ResumeOutcome::Declined))
            && repository.terminal_statuses() == vec![TerminalStatus::Declined]
            && invoker.call_count() == 0
    );
}

#[tokio::test]
async fn decline_can_reinvoke_without_declined_input_when_explicitly_planned() {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::InvokeWithoutInput,
    )
    .await;
    let result = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response("publish_approval", json!({"action": "decline"})),
        ))
        .await;
    let calls = invoker.take_calls();

    assert!(
        matches!(result, Ok(ResumeOutcome::Complete(_)))
            && calls.len() == 1
            && calls[0].arguments["approved"] == json!(false)
    );
}

#[tokio::test]
async fn mixed_accept_and_decline_has_distinct_audit_outcome() {
    let approval = approval_plan(2, DeclineBehavior::InvokeWithoutInput)
        .requests()
        .values()
        .next()
        .expect("approval request should exist")
        .clone();
    let note = note_plan(2)
        .requests()
        .values()
        .next()
        .expect("note request should exist")
        .clone();
    let plan = ElicitationPlan::try_new(
        vec![
            (
                InputRequestKey::try_new("publish_approval").expect("key should be valid"),
                approval,
            ),
            (
                InputRequestKey::try_new("note").expect("key should be valid"),
                note,
            ),
        ],
        2,
        DeclineBehavior::InvokeWithoutInput,
    )
    .expect("mixed plan should be valid");
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let challenge = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(true),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan,
        })
        .await
        .expect("mixed challenge should be issued");
    let result = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            BTreeMap::from([
                (
                    "note".to_owned(),
                    json!({"action": "accept", "content": {"note": "accepted-value"}}),
                ),
                ("publish_approval".to_owned(), json!({"action": "decline"})),
            ]),
        ))
        .await;
    let calls = invoker.take_calls();
    assert!(
        matches!(result, Ok(ResumeOutcome::Complete(_)))
            && calls.len() == 1
            && calls[0].arguments["note"] == json!("accepted-value")
            && repository.event_kinds()
                == vec![
                    MrtrAuditKind::Issued,
                    MrtrAuditKind::Claimed,
                    MrtrAuditKind::PartiallyAccepted,
                    MrtrAuditKind::Completed,
                ]
    );
}

#[tokio::test]
async fn cancellation_completes_normally_without_invocation() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let challenge = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::InvokeWithoutInput,
    )
    .await;
    let result = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response("publish_approval", json!({"action": "cancel"})),
        ))
        .await;

    assert!(
        matches!(result, Ok(ResumeOutcome::Cancelled))
            && repository.terminal_statuses() == vec![TerminalStatus::Cancelled]
            && invoker.call_count() == 0
    );
}

#[tokio::test]
async fn declined_and_cancelled_handles_cannot_be_replayed() {
    for action in ["decline", "cancel"] {
        let invoker = MemoryInvoker::default();
        let service = test_service(MemoryRepository::default(), invoker.clone());
        let challenge = begin_approval(
            &service,
            MrtrMethod::ToolCall,
            2,
            DeclineBehavior::CompleteDeclined,
        )
        .await;
        let first = service
            .resume(resume_request(
                &challenge,
                invocation(MrtrMethod::ToolCall),
                response("publish_approval", json!({"action": action})),
            ))
            .await;
        let replay = service
            .resume(resume_request(
                &challenge,
                invocation(MrtrMethod::ToolCall),
                response("publish_approval", json!({"action": action})),
            ))
            .await;
        assert!(
            matches!(
                first,
                Ok(ResumeOutcome::Declined | ResumeOutcome::Cancelled)
            ) && matches!(replay, Err(LifecycleError::StateRejected))
                && invoker.call_count() == 0
        );
    }
}

#[test]
fn credential_and_password_forms_are_prohibited_even_if_misclassified() {
    for (name, sensitivity) in [
        ("value", Sensitivity::Password),
        ("provider_api_key", Sensitivity::Public),
        ("clientSecret", Sensitivity::Public),
        ("oauth_token", Sensitivity::Public),
        ("secret", Sensitivity::Public),
        ("token", Sensitivity::Public),
        ("recovery_code", Sensitivity::Public),
        ("mfa_code", Sensitivity::Public),
        ("pat", Sensitivity::Public),
        ("seed", Sensitivity::Public),
        ("passcode", Sensitivity::Public),
        ("verification_code", Sensitivity::Public),
        ("security_code", Sensitivity::Public),
        ("2fa_code", Sensitivity::Public),
        ("recovery_key", Sensitivity::Public),
    ] {
        let field = FieldPlan::try_new(name, "/note", sensitivity).expect("field shape is valid");
        let mut properties = serde_json::Map::new();
        properties.insert(name.to_owned(), json!({"type": "string"}));
        let result = FormElicitationPlan::try_new(
            "Provide value",
            json!({"type": "object", "properties": properties}),
            vec![field],
            FormProtection::StrongConfirmation,
        );
        assert!(matches!(result, Err(PlanError::ProhibitedCredentialForm)));
    }
}

#[tokio::test]
async fn sensitive_form_requires_fresh_authoritative_confirmation() {
    let field = FieldPlan::try_new("note", "/note", Sensitivity::Confidential)
        .expect("confidential field should be valid");
    let form = FormElicitationPlan::try_new(
        "Provide a confidential note",
        json!({
            "type": "object",
            "required": ["note"],
            "properties": {"note": {"type": "string", "maxLength": 100}}
        }),
        vec![field],
        FormProtection::StrongConfirmation,
    )
    .expect("confirmed confidential form should be valid");
    let plan = ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("confidential_note").expect("key should be valid"),
            PlannedElicitation::Form(form),
        )],
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("confidential plan should be valid");
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker.clone());
    let without_confirmation = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(true),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: plan.clone(),
        })
        .await;
    assert!(
        matches!(
            without_confirmation,
            Err(LifecycleError::ConfirmationRequired)
        ) && repository.pending_count() == 0
    );

    let challenge = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(true),
            confirmation_evidence: ConfirmationEvidence::Confirmed,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: plan.clone(),
        })
        .await
        .expect("confirmed request should issue a challenge");
    let changed_evidence = service
        .resume(resume_request(
            &challenge,
            invocation(MrtrMethod::ToolCall),
            response(
                "confidential_note",
                json!({"action": "accept", "content": {"note": "classified"}}),
            ),
        ))
        .await;
    assert!(
        matches!(changed_evidence, Err(LifecycleError::ConfirmationRequired))
            && invoker.call_count() == 0
    );

    let confirmed_challenge = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(true),
            confirmation_evidence: ConfirmationEvidence::Confirmed,
            invocation: invocation(MrtrMethod::ToolCall),
            plan,
        })
        .await
        .expect("second confirmed request should issue a challenge");
    let mut confirmed_retry = resume_request(
        &confirmed_challenge,
        invocation(MrtrMethod::ToolCall),
        response(
            "confidential_note",
            json!({"action": "accept", "content": {"note": "classified"}}),
        ),
    );
    confirmed_retry.confirmation_evidence = ConfirmationEvidence::Confirmed;
    let completed = service.resume(confirmed_retry).await;
    assert!(matches!(completed, Ok(ResumeOutcome::Complete(_))) && invoker.call_count() == 1);
}

#[test]
fn credential_request_in_form_message_is_prohibited() {
    let field =
        FieldPlan::try_new("value", "/note", Sensitivity::Public).expect("field should be valid");
    let result = FormElicitationPlan::try_new(
        "Enter your provider password",
        json!({"type": "object", "properties": {"value": {"type": "string"}}}),
        vec![field],
        FormProtection::StrongConfirmation,
    );

    assert!(matches!(result, Err(PlanError::ProhibitedCredentialForm)));
}

#[test]
fn nested_credential_schema_cannot_be_rendered_as_a_form() {
    let field =
        FieldPlan::try_new("value", "/note", Sensitivity::Public).expect("field should be valid");
    let result = FormElicitationPlan::try_new(
        "Provide structured value",
        json!({
            "type": "object",
            "properties": {
                "value": {
                    "type": "object",
                    "properties": {"password": {"type": "string"}}
                }
            }
        }),
        vec![field],
        FormProtection::StrongConfirmation,
    );

    assert!(result.is_err());
}

#[test]
fn ancestor_and_descendant_argument_destinations_are_rejected() {
    let parent = FieldPlan::try_new("settings", "/settings", Sensitivity::Public)
        .expect("parent field should be valid");
    let child = FieldPlan::try_new("name", "/settings/name", Sensitivity::Public)
        .expect("child field should be valid");
    let form = FormElicitationPlan::try_new(
        "Provide settings",
        json!({
            "type": "object",
            "properties": {
                "settings": {"type": "string"},
                "name": {"type": "string"}
            }
        }),
        vec![parent, child],
        FormProtection::Ordinary,
    )
    .expect("form shape should be valid before plan-wide destination checks");
    let result = ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("settings").expect("key should be valid"),
            PlannedElicitation::Form(form),
        )],
        2,
        DeclineBehavior::CompleteDeclined,
    );

    assert!(matches!(result, Err(PlanError::DuplicateField)));
}

#[test]
fn confidential_form_requires_explicit_strong_confirmation() {
    let ordinary_field = FieldPlan::try_new("note", "/note", Sensitivity::Confidential)
        .expect("field should be valid");
    let ordinary = FormElicitationPlan::try_new(
        "Provide note",
        json!({"type": "object", "properties": {"note": {"type": "string"}}}),
        vec![ordinary_field],
        FormProtection::Ordinary,
    );
    let confirmed_field = FieldPlan::try_new("note", "/note", Sensitivity::Confidential)
        .expect("field should be valid");
    let confirmed = FormElicitationPlan::try_new(
        "Provide note",
        json!({"type": "object", "properties": {"note": {"type": "string"}}}),
        vec![confirmed_field],
        FormProtection::StrongConfirmation,
    );

    assert!(matches!(ordinary, Err(PlanError::StrongConfirmationRequired)) && confirmed.is_ok());
}

#[tokio::test]
async fn credential_flow_uses_negotiated_url_mode_without_response_content() {
    let invoker = MemoryInvoker::default();
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let challenge = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::url(),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: url_plan(2, Sensitivity::Credential),
        })
        .await
        .expect("URL mode should be issued");
    let result = service
        .resume(ResumeRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::url(),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            request_state: challenge.request_state.expose_for_wire().to_owned(),
            input_responses: response("provider_authorization", json!({"action": "accept"})),
        })
        .await;

    assert!(matches!(result, Ok(ResumeOutcome::Complete(_))) && invoker.call_count() == 1);
}

#[tokio::test]
async fn follow_up_round_carries_only_application_owned_durable_continuation() {
    let second_plan = note_plan(2);
    let continuation = InvocationContinuation::new(Uuid::now_v7());
    let invoker = MemoryInvoker::with_outcomes(vec![InvocationDisposition::InputRequired {
        plan: second_plan.clone(),
        continuation,
    }]);
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), invoker.clone());
    let first = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        10,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let first_result = service
        .resume(resume_request(
            &first,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        ))
        .await;
    let Ok(ResumeOutcome::InputRequired(second)) = first_result else {
        panic!("normal invocation should issue a second round");
    };
    let final_result = service
        .resume(resume_request(
            &second,
            invocation(MrtrMethod::ToolCall),
            response(
                "note",
                json!({"action": "accept", "content": {"note": "final note"}}),
            ),
        ))
        .await;
    let calls = invoker.take_calls();

    assert!(
        matches!(final_result, Ok(ResumeOutcome::Complete(_)))
            && second.round == 2
            && second.plan == second_plan
            && repository.pending_count() == 0
            && repository.replacement_reasons() == vec![ReplacementReason::MoreInput]
            && calls.len() == 2
            && calls[0].continuation.is_none()
            && calls[1].continuation == Some(continuation)
            && calls[0].context.canonical().invocation().request_id()
                != calls[1].context.canonical().invocation().request_id()
            && calls[1].arguments["approved"] == json!(false)
            && calls[1].arguments["note"] == json!("final note")
    );
}

#[tokio::test]
async fn fresh_confirmation_can_authorize_a_sensitive_follow_up_round() {
    let field = FieldPlan::try_new("note", "/note", Sensitivity::Confidential)
        .expect("confidential field should be valid");
    let form = FormElicitationPlan::try_new(
        "Provide a confidential follow-up",
        json!({
            "type": "object",
            "required": ["note"],
            "properties": {"note": {"type": "string", "maxLength": 100}}
        }),
        vec![field],
        FormProtection::StrongConfirmation,
    )
    .expect("confidential form should be valid");
    let sensitive_plan = ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("confidential_note").expect("key should be valid"),
            PlannedElicitation::Form(form),
        )],
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("sensitive follow-up plan should be valid");
    let continuation = InvocationContinuation::new(Uuid::now_v7());
    let invoker = MemoryInvoker::with_outcomes(vec![InvocationDisposition::InputRequired {
        plan: sensitive_plan,
        continuation,
    }]);
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let first = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let mut first_retry = resume_request(
        &first,
        invocation(MrtrMethod::ToolCall),
        response(
            "publish_approval",
            json!({"action": "accept", "content": {"approved": true}}),
        ),
    );
    first_retry.confirmation_evidence = ConfirmationEvidence::Confirmed;
    let Ok(ResumeOutcome::InputRequired(second)) = service.resume(first_retry).await else {
        panic!("fresh confirmation should authorize the sensitive follow-up");
    };
    let mut second_retry = resume_request(
        &second,
        invocation(MrtrMethod::ToolCall),
        response(
            "confidential_note",
            json!({"action": "accept", "content": {"note": "classified"}}),
        ),
    );
    second_retry.confirmation_evidence = ConfirmationEvidence::Confirmed;
    let result = service.resume(second_retry).await;
    assert!(matches!(result, Ok(ResumeOutcome::Complete(_))) && invoker.call_count() == 2);
}

#[tokio::test]
async fn follow_up_mapping_is_validated_before_a_fresh_state_is_issued() {
    let field = FieldPlan::try_new("note", "/missing/note", Sensitivity::Public)
        .expect("field should be valid");
    let form = FormElicitationPlan::try_new(
        "Provide a follow-up note",
        json!({
            "type": "object",
            "properties": {"note": {"type": "string"}},
            "required": ["note"]
        }),
        vec![field],
        FormProtection::Ordinary,
    )
    .expect("form should be valid");
    let next_plan = ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("follow_up").expect("key should be valid"),
            PlannedElicitation::Form(form),
        )],
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("plan should be structurally valid");
    let continuation = InvocationContinuation::new(Uuid::now_v7());
    let invoker = MemoryInvoker::with_outcomes(vec![InvocationDisposition::InputRequired {
        plan: next_plan,
        continuation,
    }]);
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), invoker);
    let first = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let result = service
        .resume(resume_request(
            &first,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        ))
        .await;

    assert!(
        matches!(
            result,
            Err(LifecycleError::InvalidPlan(
                PlanError::InvalidArgumentPointer
            ))
        ) && repository.pending_count() == 0
            && repository.terminal_statuses() == vec![TerminalStatus::Rejected]
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "the two-round mapping contract keeps both argument shapes visible"
)]
#[tokio::test]
async fn follow_up_mapping_uses_the_original_argument_shape() {
    let first_field = FieldPlan::try_new("settings", "/settings", Sensitivity::Public)
        .expect("field should be valid");
    let first_form = FormElicitationPlan::try_new(
        "Replace settings",
        json!({
            "type": "object",
            "properties": {"settings": {"type": "string"}},
            "required": ["settings"]
        }),
        vec![first_field],
        FormProtection::Ordinary,
    )
    .expect("form should be valid");
    let first_plan = ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("settings").expect("key should be valid"),
            PlannedElicitation::Form(first_form),
        )],
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("plan should be valid");
    let next_field = FieldPlan::try_new("name", "/settings/name", Sensitivity::Public)
        .expect("field should be valid");
    let next_form = FormElicitationPlan::try_new(
        "Provide the settings name",
        json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"]
        }),
        vec![next_field],
        FormProtection::Ordinary,
    )
    .expect("form should be valid");
    let next_plan = ElicitationPlan::try_new(
        vec![(
            InputRequestKey::try_new("name").expect("key should be valid"),
            PlannedElicitation::Form(next_form),
        )],
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .expect("plan should be valid");
    let continuation = InvocationContinuation::new(Uuid::now_v7());
    let invoker = MemoryInvoker::with_outcomes(vec![InvocationDisposition::InputRequired {
        plan: next_plan,
        continuation,
    }]);
    let service = test_service(MemoryRepository::default(), invoker.clone());
    let original = || {
        OriginalInvocation::new(
            binding(MrtrMethod::ToolCall),
            json!({"settings": {"name": ""}}),
            Some("ordinary-idempotency-key".to_owned()),
        )
    };
    let first = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: original(),
            plan: first_plan,
        })
        .await
        .expect("first challenge should be issued");
    let first_result = service
        .resume(ResumeRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: original(),
            request_state: first.request_state.expose_for_wire().to_owned(),
            input_responses: response(
                "settings",
                json!({"action": "accept", "content": {"settings": "replaced"}}),
            ),
        })
        .await;
    let Ok(ResumeOutcome::InputRequired(second)) = first_result else {
        panic!("original object shape should allow the follow-up");
    };
    let final_result = service
        .resume(ResumeRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: original(),
            request_state: second.request_state.expose_for_wire().to_owned(),
            input_responses: response(
                "name",
                json!({"action": "accept", "content": {"name": "final"}}),
            ),
        })
        .await;
    let calls = invoker.take_calls();

    assert!(
        matches!(final_result, Ok(ResumeOutcome::Complete(_)))
            && calls.len() == 2
            && calls[0].arguments["settings"] == json!("replaced")
            && calls[1].arguments["settings"]["name"] == json!("final")
    );
}

#[tokio::test]
async fn follow_up_mode_is_rechecked_before_a_fresh_state_is_issued() {
    let continuation = InvocationContinuation::new(Uuid::now_v7());
    let invoker = MemoryInvoker::with_outcomes(vec![InvocationDisposition::InputRequired {
        plan: url_plan(2, Sensitivity::Credential),
        continuation,
    }]);
    let repository = MemoryRepository::default();
    let service = test_service(repository.clone(), invoker);
    let first = begin_approval(
        &service,
        MrtrMethod::ToolCall,
        2,
        DeclineBehavior::CompleteDeclined,
    )
    .await;
    let result = service
        .resume(resume_request(
            &first,
            invocation(MrtrMethod::ToolCall),
            response(
                "publish_approval",
                json!({"action": "accept", "content": {"approved": true}}),
            ),
        ))
        .await;

    assert!(
        matches!(result, Err(LifecycleError::UnsupportedMode))
            && repository.pending_count() == 0
            && repository.terminal_statuses() == vec![TerminalStatus::Rejected]
    );
}

#[tokio::test]
async fn state_audit_and_debug_surfaces_redact_tokens_arguments_and_responses() {
    let repository = MemoryRepository::default();
    let invoker = MemoryInvoker::default();
    let service = test_service(repository.clone(), invoker);
    let challenge = service
        .begin(BeginRequest {
            context: request_context(MRTR_EXTENSION_REVISION),
            client_capabilities: ClientElicitationCapabilities::form(false),
            confirmation_evidence: ConfirmationEvidence::NotProvided,
            invocation: invocation(MrtrMethod::ToolCall),
            plan: note_plan(2),
        })
        .await
        .expect("note challenge should be issued");
    let request = ResumeRequest {
        context: request_context(MRTR_EXTENSION_REVISION),
        client_capabilities: ClientElicitationCapabilities::form(false),
        confirmation_evidence: ConfirmationEvidence::NotProvided,
        invocation: invocation(MrtrMethod::ToolCall),
        request_state: challenge.request_state.expose_for_wire().to_owned(),
        input_responses: response(
            "note",
            json!({"action": "accept", "content": {"note": "response-secret"}}),
        ),
    };
    let request_debug = format!("{request:?}");
    service
        .resume(request)
        .await
        .expect("valid response should complete");
    let combined = format!(
        "{} {} {} {:?} {:?} {:?}",
        repository.snapshot(),
        repository.audit_snapshot(),
        request_debug,
        challenge.request_state,
        LifecycleError::StateRejected,
        WireError::LossySchema,
    );

    assert!(
        !combined.contains("original-secret")
            && !combined.contains("response-secret")
            && !combined.contains(challenge.request_state.expose_for_wire())
            && combined.contains("[REDACTED]")
    );
}
