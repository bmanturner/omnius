//! Behavioral contracts for authorized bounded LLM tool execution.

use std::{
    error::Error,
    future::pending,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityKind, CapabilityRegistry,
    CapabilityRegistryBuilder, ConfirmationEvidence, ConfirmationPolicy, Exposure, HandlerError,
    HandlerInvocation, IdempotencyKey, IdempotencyPolicy, InvocationContext, ObjectSchema,
    RuntimeAvailability, SideEffect, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use omnius_llm_core::{
    LlmRequestId, ProviderStreamEvent, ProviderToolCallDelta, RawRetentionPolicy, RetainedRaw,
};
use omnius_llm_tool_runtime::{
    AgentLoopBudget, AuthorizedToolInvocation, CompleteToolCall, CompleteToolCallError,
    LoopBudgetDimension, LoopBudgetError, LoopBudgetLimits, SideEffectApproval, ToolAuditError,
    ToolAuditOutcome, ToolAuditPort, ToolAuditRecord, ToolAuthorizationBinding,
    ToolAuthorizationError, ToolAuthorizationPort, ToolAuthorizationRequest, ToolExecutionEvidence,
    ToolRuntime, ToolRuntimeError, ToolRuntimeLimits,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct CountingHandler {
    calls: Arc<AtomicUsize>,
    output: Value,
}

#[async_trait]
impl CapabilityHandler for CountingHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.output.clone())
    }
}

#[derive(Clone)]
struct Authorization {
    context: InvocationContext,
    approval: SideEffectApproval,
    failure: Option<ToolAuthorizationError>,
    cached_binding: Option<Arc<Mutex<Option<ToolAuthorizationBinding>>>>,
    observed_idempotency_keys: Option<Arc<Mutex<Vec<String>>>>,
}

#[async_trait]
impl ToolAuthorizationPort for Authorization {
    async fn authorize(
        &self,
        request: ToolAuthorizationRequest<'_>,
    ) -> Result<AuthorizedToolInvocation, ToolAuthorizationError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let requested_binding = request.binding();
        let authorization_binding = if let Some(cache) = &self.cached_binding {
            let mut cache = cache
                .lock()
                .map_err(|_| ToolAuthorizationError::Unavailable)?;
            cache.get_or_insert(requested_binding).clone()
        } else {
            requested_binding
        };
        if let Some(observed) = &self.observed_idempotency_keys {
            observed
                .lock()
                .map_err(|_| ToolAuthorizationError::Unavailable)?
                .push(
                    request
                        .idempotency_key()
                        .map_or_else(String::new, |key| key.as_str().to_owned()),
                );
        }
        Ok(AuthorizedToolInvocation::new(
            request.capability().clone(),
            self.context.clone(),
            request.tenant_mode(),
            request.confirmation(),
            request.idempotency_key().cloned(),
            self.approval,
            authorization_binding,
        ))
    }
}

#[derive(Clone, Copy)]
struct PendingAuthorization;

#[async_trait]
impl ToolAuthorizationPort for PendingAuthorization {
    async fn authorize(
        &self,
        _request: ToolAuthorizationRequest<'_>,
    ) -> Result<AuthorizedToolInvocation, ToolAuthorizationError> {
        pending().await
    }
}

#[derive(Clone, Default)]
struct AuditCapture {
    outcomes: Arc<Mutex<Vec<ToolAuditOutcome>>>,
    fail: bool,
}

impl ToolAuditPort for AuditCapture {
    fn record(&self, record: ToolAuditRecord) -> Result<(), ToolAuditError> {
        if self.fail {
            return Err(ToolAuditError::Unavailable);
        }
        self.outcomes
            .lock()
            .map_err(|_| ToolAuditError::Unavailable)?
            .push(record.outcome());
        Ok(())
    }
}

fn document() -> Result<CapabilityDocument, Box<dyn Error>> {
    Ok(CapabilityDocument {
        id: "widgets.update".parse()?,
        version: "1.0.0".parse()?,
        title: "Update widget".parse()?,
        kind: CapabilityKind::Command,
        description: None,
        input_schema: object_schema(json!({
            "type": "object",
            "properties": {"value": {"type": "integer"}},
            "required": ["value"],
            "additionalProperties": false
        }))?,
        output_schema: object_schema(json!({
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": false
        }))?,
        permissions: vec!["widgets:write".parse()?],
        side_effect: SideEffect::Mutating,
        confirmation: ConfirmationPolicy::Always,
        idempotency: IdempotencyPolicy::Required,
        tenant_modes: vec![TenantMode::Tenant],
        exposures: vec![Exposure::LlmTool],
        deprecated: false,
    })
}

fn object_schema(value: Value) -> Result<ObjectSchema, Box<dyn Error>> {
    Ok(ObjectSchema::try_from(value)?)
}

fn registry(calls: Arc<AtomicUsize>, output: Value) -> Result<CapabilityRegistry, Box<dyn Error>> {
    registry_with_document(document()?, calls, output)
}

fn registry_with_document(
    document: CapabilityDocument,
    calls: Arc<AtomicUsize>,
    output: Value,
) -> Result<CapabilityRegistry, Box<dyn Error>> {
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document,
        RuntimeAvailability::Available,
        CountingHandler { calls, output },
    )?;
    Ok(builder.build())
}

fn principal(tenant_id: TenantId) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::new(),
        PrincipalKind::User,
        Some(tenant_id),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn context(
    output_bytes: u64,
    cancellation: CancellationToken,
    deadline: OffsetDateTime,
) -> Result<InvocationContext, Box<dyn Error>> {
    let tenant_id = TenantId::new();
    Ok(InvocationContext::new(
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal(tenant_id)?,
        Some(tenant_id),
        Decision::Allow,
        "policy.default".parse()?,
        BudgetBounds::new(1_024, output_bytes, 100)?,
        deadline,
        cancellation,
    )?)
}

fn authorization(
    approval: SideEffectApproval,
    output_bytes: u64,
) -> Result<Authorization, Box<dyn Error>> {
    Ok(Authorization {
        context: context(
            output_bytes,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        )?,
        approval,
        failure: None,
        cached_binding: None,
        observed_idempotency_keys: None,
    })
}

fn call(
    call_id: &str,
    correlation_id: &str,
    arguments: Value,
) -> Result<CompleteToolCall, Box<dyn Error>> {
    Ok(CompleteToolCall::try_from(ProviderStreamEvent::ToolCall {
        sequence: 3,
        correlation_id: correlation_id.to_owned(),
        call_id: call_id.to_owned(),
        name: "widgets.update".to_owned(),
        arguments,
        raw: RetainedRaw::from_value(RawRetentionPolicy::Discard, json!(null)),
    })?)
}

fn request_id() -> Result<LlmRequestId, Box<dyn Error>> {
    Ok(LlmRequestId::new("request-t157".to_owned())?)
}

fn evidence() -> Result<ToolExecutionEvidence, Box<dyn Error>> {
    Ok(ToolExecutionEvidence::new(
        TenantMode::Tenant,
        ConfirmationEvidence::Confirmed,
        None,
        request_id()?,
    ))
}

fn runtime_limits(output_bytes: u64) -> Result<ToolRuntimeLimits, Box<dyn Error>> {
    Ok(ToolRuntimeLimits::new(
        NonZeroUsize::new(16).ok_or("invalid catalog limit")?,
        NonZeroUsize::new(32).ok_or("invalid call limit")?,
        NonZeroU64::new(1_024).ok_or("invalid argument limit")?,
        NonZeroU64::new(output_bytes).ok_or("invalid output limit")?,
    ))
}

fn loop_budget(
    limits: LoopBudgetLimits,
    start: OffsetDateTime,
) -> Result<AgentLoopBudget, Box<dyn Error>> {
    Ok(AgentLoopBudget::new(limits, start)?)
}

fn generous_loop_limits() -> Result<LoopBudgetLimits, Box<dyn Error>> {
    Ok(LoopBudgetLimits::new(
        8,
        16,
        time::Duration::hours(1),
        10_000,
        10_000,
        4,
    )?)
}

#[test]
fn argument_fragments_cannot_become_complete_calls() {
    let fragment = ProviderStreamEvent::ToolCallDelta {
        sequence: 1,
        correlation_id: "correlation-secret".to_owned(),
        delta: ProviderToolCallDelta::ArgumentsFragment("{\"value\":".to_owned()),
    };

    assert!(matches!(
        CompleteToolCall::try_from(fragment),
        Err(CompleteToolCallError::NotComplete)
    ));
}

#[test]
fn catalog_projects_only_available_llm_tool_exposure() -> Result<(), Box<dyn Error>> {
    let mut http_only = document()?;
    http_only.exposures = vec![Exposure::Http];
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry_with_document(http_only, Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert!(runtime.catalog().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn every_local_pre_invocation_guard_keeps_handler_count_zero() -> Result<(), Box<dyn Error>> {
    let cases = [
        (
            call("bad-schema", "correlation-1", json!({"value": "wrong"}))?,
            evidence()?,
            authorization(SideEffectApproval::Approved, 1_024)?,
            ToolRuntimeError::ArgumentsInvalid,
        ),
        (
            call("bad-tenant", "correlation-2", json!({"value": 1}))?,
            ToolExecutionEvidence::new(
                TenantMode::Global,
                ConfirmationEvidence::Confirmed,
                None,
                request_id()?,
            ),
            authorization(SideEffectApproval::Approved, 1_024)?,
            ToolRuntimeError::TenantGuardRejected,
        ),
        (
            call("no-confirmation", "correlation-3", json!({"value": 1}))?,
            ToolExecutionEvidence::new(
                TenantMode::Tenant,
                ConfirmationEvidence::NotProvided,
                None,
                request_id()?,
            ),
            authorization(SideEffectApproval::Approved, 1_024)?,
            ToolRuntimeError::ConfirmationGuardRejected,
        ),
        (
            call("no-side-approval", "correlation-4", json!({"value": 1}))?,
            evidence()?,
            authorization(SideEffectApproval::NotRequired, 1_024)?,
            ToolRuntimeError::SideEffectApprovalRejected,
        ),
        (
            call("weak-output-bound", "correlation-5", json!({"value": 1}))?,
            evidence()?,
            authorization(SideEffectApproval::Approved, 2_048)?,
            ToolRuntimeError::OutputLimitNotEnforced,
        ),
        (
            call(
                "oversized-arguments",
                "correlation-6",
                json!({"value": 1, "padding": "x".repeat(2_048)}),
            )?,
            evidence()?,
            authorization(SideEffectApproval::Approved, 1_024)?,
            ToolRuntimeError::ArgumentsTooLarge,
        ),
    ];

    for (complete_call, evidence, authorization, expected) in cases {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
        let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
        let runtime = ToolRuntime::new(
            &registry,
            authorization,
            AuditCapture::default(),
            &budget,
            runtime_limits(1_024)?,
        )?;
        assert_eq!(
            runtime.execute(&complete_call, &evidence).await.err(),
            Some(expected)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn exhausted_tool_call_budget_keeps_handler_count_zero() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(
        LoopBudgetLimits::new(1, 0, time::Duration::hours(1), 1_000, 1_000, 1)?,
        OffsetDateTime::now_utc(),
    )?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert_eq!(
        runtime
            .execute(
                &call("no-budget", "budget-correlation", json!({"value": 1}))?,
                &evidence()?
            )
            .await
            .err(),
        Some(ToolRuntimeError::LoopBudget(LoopBudgetDimension::ToolCalls))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn denied_exact_authorization_keeps_handler_count_zero() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let mut authorization = authorization(SideEffectApproval::Approved, 1_024)?;
    authorization.failure = Some(ToolAuthorizationError::Denied);
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    let denied_call = call("denied", "denied-correlation", json!({"value": 1}))?;
    for _ in 0..2 {
        assert_eq!(
            runtime.execute(&denied_call, &evidence()?).await.err(),
            Some(ToolRuntimeError::Authorization(
                ToolAuthorizationError::Denied
            ))
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn cancelled_authorized_context_keeps_handler_count_zero() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let authorization = Authorization {
        context: context(
            1_024,
            cancellation,
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        )?,
        approval: SideEffectApproval::Approved,
        failure: None,
        cached_binding: None,
        observed_idempotency_keys: None,
    };
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert_eq!(
        runtime
            .execute(
                &call("cancelled", "cancelled-correlation", json!({"value": 1}))?,
                &evidence()?
            )
            .await
            .err(),
        Some(ToolRuntimeError::Cancelled)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn expired_authorized_deadline_keeps_handler_count_zero() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let authorization = Authorization {
        context: context(
            1_024,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::milliseconds(10),
        )?,
        approval: SideEffectApproval::Approved,
        failure: None,
        cached_binding: None,
        observed_idempotency_keys: None,
    };
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert_eq!(
        runtime
            .execute(
                &call("expired", "expired-correlation", json!({"value": 1}))?,
                &evidence()?
            )
            .await
            .err(),
        Some(ToolRuntimeError::DeadlineExceeded)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn pending_authorization_is_cut_off_by_loop_wall_clock_before_handler()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let now = OffsetDateTime::now_utc();
    let budget = loop_budget(
        LoopBudgetLimits::new(1, 1, time::Duration::milliseconds(10), 1_000, 1_000, 1)?,
        now,
    )?;
    let runtime = ToolRuntime::new(
        &registry,
        PendingAuthorization,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert_eq!(
        runtime
            .execute(
                &call("pending-authz", "pending-correlation", json!({"value": 1}))?,
                &evidence()?
            )
            .await
            .err(),
        Some(ToolRuntimeError::LoopBudget(LoopBudgetDimension::WallClock))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn inapplicable_supplied_idempotency_key_keeps_handler_count_zero()
-> Result<(), Box<dyn Error>> {
    let mut safe_document = document()?;
    safe_document.kind = CapabilityKind::Query;
    safe_document.side_effect = SideEffect::None;
    safe_document.confirmation = ConfirmationPolicy::Never;
    safe_document.idempotency = IdempotencyPolicy::NotApplicable;
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry_with_document(safe_document, Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::NotRequired, 1_024)?,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;
    let evidence = ToolExecutionEvidence::new(
        TenantMode::Tenant,
        ConfirmationEvidence::NotProvided,
        Some(IdempotencyKey::new("explicit-key".to_owned())?),
        request_id()?,
    );

    assert_eq!(
        runtime
            .execute(
                &call(
                    "unexpected-key",
                    "idempotency-correlation",
                    json!({"value": 1})
                )?,
                &evidence,
            )
            .await
            .err(),
        Some(ToolRuntimeError::IdempotencyGuardRejected)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn duplicate_and_concurrent_call_identity_executes_handler_exactly_once()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let audit = AuditCapture::default();
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        audit.clone(),
        &budget,
        runtime_limits(1_024)?,
    )?;
    let complete_call = call("same-call", "same-correlation", json!({"value": 1}))?;

    let first_evidence = evidence()?;
    let second_evidence = evidence()?;
    let (first, second) = tokio::join!(
        runtime.execute(&complete_call, &first_evidence),
        runtime.execute(&complete_call, &second_evidence)
    );
    let successes = usize::from(first.is_ok()) + usize::from(second.is_ok());

    assert_eq!((successes, calls.load(Ordering::SeqCst)), (1, 1));
    assert_eq!(
        audit.outcomes.lock().map_err(|_| "audit poisoned")?.len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn handler_output_is_bounded_and_schema_validated_after_one_execution()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": "secret-invalid"}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert_eq!(
        runtime
            .execute(
                &call("bad-output", "output-correlation", json!({"value": 1}))?,
                &evidence()?
            )
            .await
            .err(),
        Some(ToolRuntimeError::OutputInvalid)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn audit_and_debug_output_remain_redacted_and_audit_is_synchronous()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let audit = AuditCapture::default();
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        audit.clone(),
        &budget,
        runtime_limits(1_024)?,
    )?;
    let secret = "never-render-tool-secret";
    let complete_call = call(
        "redacted-call",
        "redacted-correlation",
        json!({"value": secret}),
    )?;
    let Err(error) = runtime.execute(&complete_call, &evidence()?).await else {
        return Err(std::io::Error::other("expected invalid arguments").into());
    };
    let rendered = format!("{complete_call:?} {error:?}");

    assert!(!rendered.contains(secret));
    assert_eq!(
        audit
            .outcomes
            .lock()
            .map_err(|_| "audit poisoned")?
            .as_slice(),
        &[ToolAuditOutcome::InvalidArguments]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn audit_failure_is_returned_only_after_the_synchronous_record_attempt()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let audit = AuditCapture {
        outcomes: Arc::new(Mutex::new(Vec::new())),
        fail: true,
    };
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        audit,
        &budget,
        runtime_limits(1_024)?,
    )?;

    assert_eq!(
        runtime
            .execute(
                &call("audit-fail", "audit-correlation", json!({"value": 1}))?,
                &evidence()?
            )
            .await
            .err(),
        Some(ToolRuntimeError::AuditUnavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn required_idempotency_is_derived_and_exact_revision_provenance_is_preserved()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let runtime = ToolRuntime::new(
        &registry,
        authorization(SideEffectApproval::Approved, 1_024)?,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;
    let result = runtime
        .execute(
            &call("derived-key", "derived-correlation", json!({"value": 1}))?,
            &evidence()?,
        )
        .await?;

    assert_eq!(
        (
            result.capability().id().as_str(),
            result.capability().version().as_str(),
            result.identity().call_id(),
            calls.load(Ordering::SeqCst),
        ),
        ("widgets.update", "1.0.0", "derived-key", 1)
    );
    Ok(())
}
#[tokio::test]
async fn cached_authorization_grant_cannot_cross_policy_questions() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let mut authorization = authorization(SideEffectApproval::Approved, 1_024)?;
    authorization.cached_binding = Some(Arc::new(Mutex::new(None)));
    let runtime = ToolRuntime::new(
        &registry,
        authorization,
        AuditCapture::default(),
        &budget,
        runtime_limits(1_024)?,
    )?;
    runtime
        .execute(
            &call("binding-a", "binding-correlation-a", json!({"value": 1}))?,
            &evidence()?,
        )
        .await?;
    assert_eq!(
        runtime
            .execute(
                &call("binding-b", "binding-correlation-b", json!({"value": 2}))?,
                &evidence()?,
            )
            .await
            .err(),
        Some(ToolRuntimeError::AuthorizationGrantMismatch)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn derived_idempotency_is_scoped_by_canonical_request_identity() -> Result<(), Box<dyn Error>>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(Arc::clone(&calls), json!({"ok": true}))?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut authorization = authorization(SideEffectApproval::Approved, 1_024)?;
    authorization.observed_idempotency_keys = Some(Arc::clone(&observed));
    let first_budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let second_budget = loop_budget(generous_loop_limits()?, OffsetDateTime::now_utc())?;
    let first = ToolRuntime::new(
        &registry,
        authorization.clone(),
        AuditCapture::default(),
        &first_budget,
        runtime_limits(1_024)?,
    )?;
    let second = ToolRuntime::new(
        &registry,
        authorization,
        AuditCapture::default(),
        &second_budget,
        runtime_limits(1_024)?,
    )?;
    let first_evidence = ToolExecutionEvidence::new(
        TenantMode::Tenant,
        ConfirmationEvidence::Confirmed,
        None,
        LlmRequestId::new("request-scope-a".to_owned())?,
    );
    let second_evidence = ToolExecutionEvidence::new(
        TenantMode::Tenant,
        ConfirmationEvidence::Confirmed,
        None,
        LlmRequestId::new("request-scope-b".to_owned())?,
    );
    let complete_call = call("same-call", "same-correlation", json!({"value": 1}))?;
    first.execute(&complete_call, &first_evidence).await?;
    second.execute(&complete_call, &second_evidence).await?;

    let keys = observed.lock().map_err(|_| "observed keys poisoned")?;
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn every_zero_loop_budget_dimension_terminates_deterministically() -> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::UNIX_EPOCH;
    let cases = [
        (
            LoopBudgetLimits::new(0, 1, time::Duration::seconds(1), 1, 1, 1)?,
            LoopBudgetDimension::ModelTurns,
        ),
        (
            LoopBudgetLimits::new(1, 0, time::Duration::seconds(1), 1, 1, 1)?,
            LoopBudgetDimension::ToolCalls,
        ),
        (
            LoopBudgetLimits::new(1, 1, time::Duration::ZERO, 1, 1, 1)?,
            LoopBudgetDimension::WallClock,
        ),
        (
            LoopBudgetLimits::new(1, 1, time::Duration::seconds(1), 0, 1, 1)?,
            LoopBudgetDimension::Tokens,
        ),
        (
            LoopBudgetLimits::new(1, 1, time::Duration::seconds(1), 1, 0, 1)?,
            LoopBudgetDimension::Cost,
        ),
        (
            LoopBudgetLimits::new(1, 1, time::Duration::seconds(1), 1, 1, 0)?,
            LoopBudgetDimension::Concurrency,
        ),
    ];

    for (limits, expected) in cases {
        let budget = loop_budget(limits, now)?;
        assert_eq!(
            budget.check_at(now),
            Err(LoopBudgetError::Exhausted(expected))
        );
    }
    Ok(())
}

#[test]
fn each_consumable_loop_budget_dimension_stops_at_its_exact_boundary() -> Result<(), Box<dyn Error>>
{
    let now = OffsetDateTime::UNIX_EPOCH;
    let model = loop_budget(
        LoopBudgetLimits::new(1, 2, time::Duration::seconds(2), 5, 7, 1)?,
        now,
    )?;
    model.reserve_model_turn_at(now)?;
    assert_eq!(
        model.reserve_model_turn_at(now),
        Err(LoopBudgetError::Exhausted(LoopBudgetDimension::ModelTurns))
    );

    let tools = loop_budget(
        LoopBudgetLimits::new(2, 1, time::Duration::seconds(2), 5, 7, 1)?,
        now,
    )?;
    tools.reserve_tool_call_at(now)?;
    assert_eq!(
        tools.reserve_tool_call_at(now),
        Err(LoopBudgetError::Exhausted(LoopBudgetDimension::ToolCalls))
    );

    let usage = loop_budget(
        LoopBudgetLimits::new(2, 2, time::Duration::seconds(2), 5, 7, 1)?,
        now,
    )?;
    usage.charge_usage_at(5, 0, now)?;
    assert_eq!(
        usage.charge_usage_at(1, 0, now),
        Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Tokens))
    );

    let cost = loop_budget(
        LoopBudgetLimits::new(2, 2, time::Duration::seconds(2), 5, 7, 1)?,
        now,
    )?;
    cost.charge_usage_at(0, 7, now)?;
    assert_eq!(
        cost.charge_usage_at(0, 1, now),
        Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Cost))
    );

    let concurrent = loop_budget(
        LoopBudgetLimits::new(2, 2, time::Duration::seconds(2), 5, 7, 1)?,
        now,
    )?;
    let permit = concurrent.try_reserve_concurrency_at(now)?;
    assert_eq!(
        concurrent.try_reserve_concurrency_at(now).err(),
        Some(LoopBudgetError::Exhausted(LoopBudgetDimension::Concurrency))
    );
    drop(permit);
    assert_eq!(
        concurrent.check_at(now + time::Duration::seconds(2)),
        Err(LoopBudgetError::Exhausted(LoopBudgetDimension::WallClock))
    );
    Ok(())
}
