//! End-to-end registry admission, guardrail, and lifecycle contracts.

use std::{
    error::Error,
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    AvailabilityReason, BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityInvocation,
    CapabilityRegistry, CapabilityRegistryBuilder, ConfirmationEvidence, ConfirmationPolicy,
    ContextError, Exposure, HandlerError, HandlerInvocation, IdempotencyPolicy, InvocationContext,
    InvocationError, ObjectSchema, RegistryBuildError, RuntimeAvailability, SideEffect, TenantMode,
    TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_core::RequestId;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

const FIXED_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/agent-capability.example.yaml");
const EXPOSURES: [Exposure; 7] = [
    Exposure::Http,
    Exposure::Job,
    Exposure::LlmTool,
    Exposure::McpTool,
    Exposure::McpResource,
    Exposure::McpPrompt,
    Exposure::Browser,
];

#[derive(Clone)]
struct CountingHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CapabilityHandler for CountingHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!([]))
    }
}

#[derive(Clone)]
struct RecordingHandler {
    observations: Arc<Mutex<Vec<Observation>>>,
}

struct Observation {
    exposure: Exposure,
    request_id: RequestId,
    tenant_id: Option<TenantId>,
    subject_id: SubjectId,
    authorization: Decision,
    budget: BudgetBounds,
    deadline: OffsetDateTime,
    traceparent: String,
    data_policy: String,
    input: Value,
}

#[async_trait]
impl CapabilityHandler for RecordingHandler {
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.observations.lock().await.push(Observation {
            exposure: invocation.exposure(),
            request_id: invocation.context().request_id(),
            tenant_id: invocation.context().tenant_id(),
            subject_id: invocation.context().principal().subject_id,
            authorization: invocation.context().authorization(),
            budget: invocation.context().budget(),
            deadline: invocation.context().deadline(),
            traceparent: invocation
                .context()
                .trace_context()
                .traceparent()
                .as_str()
                .to_owned(),
            data_policy: invocation.context().data_policy().as_str().to_owned(),
            input: invocation.input().clone(),
        });
        Ok(json!([]))
    }
}

#[derive(Clone)]
struct PendingHandler {
    calls: Arc<AtomicUsize>,
    started: Option<Arc<Notify>>,
}

#[async_trait]
impl CapabilityHandler for PendingHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(started) = &self.started {
            started.notify_one();
        }
        pending::<Result<Value, HandlerError>>().await
    }
}

#[derive(Clone, Copy)]
struct FailingHandler;

#[async_trait]
impl CapabilityHandler for FailingHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        Err(HandlerError::new(
            omnius_agent_capability_registry::HandlerErrorCode::Internal,
        ))
    }
}

#[derive(Clone)]
struct OversizedOutputHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CapabilityHandler for OversizedOutputHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"payload": "x".repeat(2_048)}))
    }
}

#[derive(Clone)]
struct SchemaHandler {
    calls: Arc<AtomicUsize>,
    output: Value,
}

#[async_trait]
impl CapabilityHandler for SchemaHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.output.clone())
    }
}

#[tokio::test]
async fn every_projection_reaches_the_same_handler_with_the_same_context()
-> Result<(), Box<dyn Error>> {
    let mut document = base_document()?;
    document.exposures = EXPOSURES.to_vec();
    let capability = document.key();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let handler = RecordingHandler {
        observations: Arc::clone(&observations),
    };
    let registry = registry(document, RuntimeAvailability::Available, handler)?;
    let tenant_id = TenantId::new();
    let principal = principal(Some(tenant_id))?;
    let request_id = RequestId::new();
    let deadline = OffsetDateTime::now_utc() + time::Duration::seconds(60);

    for exposure in EXPOSURES {
        let context = context(
            principal.clone(),
            Some(tenant_id),
            request_id,
            Decision::Allow,
            CancellationToken::new(),
            deadline,
        )?;
        let result = registry
            .invoke(
                exposure,
                CapabilityInvocation::new(
                    capability.clone(),
                    context,
                    TenantMode::Tenant,
                    json!({"query": "same-input"}),
                    ConfirmationEvidence::NotProvided,
                    None,
                ),
            )
            .await?;
        assert_eq!(result.output(), &json!([]));
    }

    let observations = observations.lock().await;
    assert_eq!(observations.len(), EXPOSURES.len());
    for (observation, exposure) in observations.iter().zip(EXPOSURES) {
        assert_eq!(observation.exposure, exposure);
        assert_eq!(observation.request_id, request_id);
        assert_eq!(observation.tenant_id, Some(tenant_id));
        assert_eq!(observation.subject_id, principal.subject_id);
        assert_eq!(observation.authorization, Decision::Allow);
        assert_eq!(observation.budget, BudgetBounds::new(1_024, 1_024, 100)?);
        assert_eq!(observation.deadline, deadline);
        assert_eq!(
            observation.traceparent,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
        assert_eq!(observation.data_policy, "policy.default");
        assert_eq!(observation.input, json!({"query": "same-input"}));
    }
    Ok(())
}

#[test]
fn duplicate_declarations_fail_closed() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = CountingHandler {
        calls: Arc::clone(&calls),
    };
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document.clone(),
        RuntimeAvailability::Available,
        handler.clone(),
    )?;
    let error = builder
        .register(document, RuntimeAvailability::Available, handler)
        .err();

    assert_eq!(error, Some(RegistryBuildError::DuplicateCapability));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn disabled_capability_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Unavailable(AvailabilityReason::DisabledByConfiguration),
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let result = registry
        .invoke(
            Exposure::Http,
            allowed_invocation(capability, CancellationToken::new())?,
        )
        .await;

    assert!(matches!(result, Err(InvocationError::Unavailable)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn denied_authorization_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let tenant_id = TenantId::new();
    let invocation = CapabilityInvocation::new(
        capability,
        context(
            principal(Some(tenant_id))?,
            Some(tenant_id),
            RequestId::new(),
            Decision::Deny(DenyReason::NotEntitled),
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(5),
        )?,
        TenantMode::Tenant,
        json!({}),
        ConfirmationEvidence::NotProvided,
        None,
    );
    let result = registry.invoke(Exposure::Http, invocation).await;

    assert!(matches!(result, Err(InvocationError::Denied)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn undeclared_exposure_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let result = registry
        .invoke(
            Exposure::Browser,
            allowed_invocation(capability, CancellationToken::new())?,
        )
        .await;

    assert!(matches!(result, Err(InvocationError::ExposureNotDeclared)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn undeclared_tenant_mode_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let base = allowed_invocation(capability, CancellationToken::new())?;
    let invocation = CapabilityInvocation::new(
        base.capability().clone(),
        base.context().clone(),
        TenantMode::Global,
        json!({}),
        ConfirmationEvidence::NotProvided,
        None,
    );
    let result = registry.invoke(Exposure::Http, invocation).await;

    assert!(matches!(result, Err(InvocationError::TenantModeMismatch)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn cross_tenant_context_is_rejected_at_construction() -> Result<(), Box<dyn Error>> {
    let principal_tenant = TenantId::new();
    let requested_tenant = TenantId::new();
    let result = context(
        principal(Some(principal_tenant))?,
        Some(requested_tenant),
        RequestId::new(),
        Decision::Allow,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + time::Duration::seconds(5),
    );

    assert!(matches!(result, Err(ContextError::TenantMismatch)));
    Ok(())
}

#[test]
fn expired_context_is_rejected_at_construction() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let result = context(
        principal(Some(tenant_id))?,
        Some(tenant_id),
        RequestId::new(),
        Decision::Allow,
        CancellationToken::new(),
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );

    assert!(matches!(result, Err(ContextError::ExpiredDeadline)));
    Ok(())
}

#[tokio::test]
async fn unconfirmed_destructive_invocation_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let mut document = base_document()?;
    document.kind = omnius_agent_capability_registry::CapabilityKind::Command;
    document.side_effect = SideEffect::Destructive;
    document.confirmation = ConfirmationPolicy::Always;
    document.idempotency = IdempotencyPolicy::Required;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let mut invocation = allowed_invocation(capability, CancellationToken::new())?;
    invocation = CapabilityInvocation::new(
        invocation.capability().clone(),
        invocation.context().clone(),
        TenantMode::Tenant,
        json!({}),
        ConfirmationEvidence::NotProvided,
        Some("operation-1".parse()?),
    );
    let result = registry.invoke(Exposure::Http, invocation).await;

    assert!(matches!(result, Err(InvocationError::ConfirmationRequired)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn missing_required_idempotency_key_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let mut document = base_document()?;
    document.kind = omnius_agent_capability_registry::CapabilityKind::Command;
    document.side_effect = SideEffect::Destructive;
    document.confirmation = ConfirmationPolicy::Always;
    document.idempotency = IdempotencyPolicy::Required;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let base = allowed_invocation(capability, CancellationToken::new())?;
    let invocation = CapabilityInvocation::new(
        base.capability().clone(),
        base.context().clone(),
        TenantMode::Tenant,
        json!({}),
        ConfirmationEvidence::Confirmed,
        None,
    );
    let result = registry.invoke(Exposure::Http, invocation).await;

    assert!(matches!(result, Err(InvocationError::IdempotencyMismatch)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn oversized_input_fails_before_handler() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let base = allowed_invocation(capability, CancellationToken::new())?;
    let invocation = CapabilityInvocation::new(
        base.capability().clone(),
        base.context().clone(),
        TenantMode::Tenant,
        json!({"payload": "x".repeat(2_048)}),
        ConfirmationEvidence::NotProvided,
        None,
    );
    let result = registry.invoke(Exposure::Http, invocation).await;

    assert!(matches!(result, Err(InvocationError::InputBudgetExceeded)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn oversized_output_fails_after_handler() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        OversizedOutputHandler {
            calls: Arc::clone(&calls),
        },
    )?;
    let result = registry
        .invoke(
            Exposure::Http,
            allowed_invocation(capability, CancellationToken::new())?,
        )
        .await;

    assert!(matches!(result, Err(InvocationError::OutputBudgetExceeded)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn invalid_schema_compilation_fails_with_a_redacted_registration_error()
-> Result<(), Box<dyn Error>> {
    let mut document = base_document()?;
    document.input_schema = ObjectSchema::try_from(json!({
        "type": "object",
        "properties": {
            "private_schema_field": {"type": 7}
        }
    }))?;
    let mut builder = CapabilityRegistryBuilder::new();
    let result = builder.register(
        document,
        RuntimeAvailability::Available,
        CountingHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    let Some(error) = result.err() else {
        return Err("invalid schema was admitted".into());
    };
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, RegistryBuildError::InvalidSchema);
    assert!(!rendered.contains("private_schema_field"));
    Ok(())
}

#[tokio::test]
async fn wrong_input_type_is_rejected_for_every_exposure_before_dispatch()
-> Result<(), Box<dyn Error>> {
    let mut document = schema_document()?;
    document.exposures = EXPOSURES.to_vec();
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        SchemaHandler {
            calls: Arc::clone(&calls),
            output: valid_schema_output(),
        },
    )?;

    for exposure in EXPOSURES {
        let result = registry
            .invoke(
                exposure,
                invocation_with_input(
                    capability.clone(),
                    json!({
                        "profile": "wrong-type",
                        "tier": "standard",
                        "score": 5,
                        "contact": "192.0.2.1"
                    }),
                )?,
            )
            .await;
        let Some(error) = result.err() else {
            return Err("wrong input type reached the handler".into());
        };
        let rendered = format!("{error:?} {error}");
        assert_eq!(error, InvocationError::InputSchemaMismatch);
        assert!(!rendered.contains("wrong-type"));
    }

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn missing_required_input_is_rejected_before_dispatch() -> Result<(), Box<dyn Error>> {
    assert_invalid_schema_input(json!({
        "profile": {"name": "Ada"},
        "tier": "standard",
        "contact": "192.0.2.1"
    }))
    .await
}

#[tokio::test]
async fn nested_additional_input_property_is_rejected_before_dispatch() -> Result<(), Box<dyn Error>>
{
    assert_invalid_schema_input(json!({
        "profile": {"name": "Ada", "private": true},
        "tier": "standard",
        "score": 5,
        "contact": "192.0.2.1"
    }))
    .await
}

#[tokio::test]
async fn enum_and_range_input_violations_are_rejected_before_dispatch() -> Result<(), Box<dyn Error>>
{
    for input in [
        json!({
            "profile": {"name": "Ada"},
            "tier": "unrecognized",
            "score": 5,
            "contact": "192.0.2.1"
        }),
        json!({
            "profile": {"name": "Ada"},
            "tier": "standard",
            "score": 11,
            "contact": "192.0.2.1"
        }),
    ] {
        assert_invalid_schema_input(input).await?;
    }
    Ok(())
}

#[tokio::test]
async fn supported_format_violation_is_rejected_before_dispatch() -> Result<(), Box<dyn Error>> {
    assert_invalid_schema_input(json!({
        "profile": {"name": "Ada"},
        "tier": "standard",
        "score": 5,
        "contact": "999.999.999.999"
    }))
    .await
}

#[tokio::test]
async fn invalid_handler_output_is_rejected_after_dispatch() -> Result<(), Box<dyn Error>> {
    let document = schema_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        SchemaHandler {
            calls: Arc::clone(&calls),
            output: json!({"accepted": "not-a-boolean"}),
        },
    )?;
    let result = registry
        .invoke(
            Exposure::Http,
            invocation_with_input(capability, valid_schema_input())?,
        )
        .await;
    let Some(error) = result.err() else {
        return Err("invalid handler output crossed the registry boundary".into());
    };
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, InvocationError::OutputSchemaMismatch);
    assert!(!rendered.contains("accepted"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn valid_input_and_output_cross_the_compiled_schema_boundary() -> Result<(), Box<dyn Error>> {
    let document = schema_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let expected = valid_schema_output();
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        SchemaHandler {
            calls: Arc::clone(&calls),
            output: expected.clone(),
        },
    )?;
    let result = registry
        .invoke(
            Exposure::Http,
            invocation_with_input(capability, valid_schema_input())?,
        )
        .await?;

    assert_eq!(result.output(), &expected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn handler_is_bounded_by_absolute_deadline() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        PendingHandler {
            calls: Arc::clone(&calls),
            started: None,
        },
    )?;
    let tenant_id = TenantId::new();
    let invocation = CapabilityInvocation::new(
        capability,
        context(
            principal(Some(tenant_id))?,
            Some(tenant_id),
            RequestId::new(),
            Decision::Allow,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(1),
        )?,
        TenantMode::Tenant,
        json!({"query": "deadline"}),
        ConfirmationEvidence::NotProvided,
        None,
    );
    let result = registry.invoke(Exposure::Http, invocation).await;

    assert!(matches!(result, Err(InvocationError::DeadlineExceeded)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn running_handler_is_bounded_by_cancellation() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let registry = Arc::new(registry(
        document,
        RuntimeAvailability::Available,
        PendingHandler {
            calls: Arc::clone(&calls),
            started: Some(Arc::clone(&started)),
        },
    )?);
    let cancellation = CancellationToken::new();
    let invocation = allowed_invocation(capability, cancellation.clone())?;
    let task = tokio::spawn({
        let registry = Arc::clone(&registry);
        async move { registry.invoke(Exposure::Http, invocation).await }
    });
    started.notified().await;
    cancellation.cancel();
    let result = task.await?;

    assert!(matches!(result, Err(InvocationError::Cancelled)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn handler_failures_cross_boundary_as_fixed_redacted_codes() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let registry = registry(document, RuntimeAvailability::Available, FailingHandler)?;
    let result = registry
        .invoke(
            Exposure::Http,
            allowed_invocation(capability, CancellationToken::new())?,
        )
        .await;

    assert!(matches!(
        result,
        Err(InvocationError::HandlerFailed(
            omnius_agent_capability_registry::HandlerErrorCode::Internal
        ))
    ));
    Ok(())
}

#[test]
fn availability_distinguishes_compiled_and_runtime_state() -> Result<(), Box<dyn Error>> {
    let document = base_document()?;
    let capability = document.key();
    let registry = registry(
        document,
        RuntimeAvailability::Unavailable(AvailabilityReason::Unhealthy),
        CountingHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    )?;
    let compiled = registry.availability(&capability);
    let missing_key = omnius_agent_capability_registry::CapabilityKey::new(
        "records.missing".parse()?,
        "1.0.0".parse()?,
    );
    let missing = registry.availability(&missing_key);

    assert!(compiled.compiled());
    assert_eq!(
        compiled.runtime(),
        RuntimeAvailability::Unavailable(AvailabilityReason::Unhealthy)
    );
    assert!(!missing.compiled());
    assert_eq!(
        missing.runtime(),
        RuntimeAvailability::Unavailable(AvailabilityReason::NotCompiled)
    );
    Ok(())
}

#[test]
fn debug_output_redacts_runtime_values() -> Result<(), Box<dyn Error>> {
    let capability = base_document()?.key();
    let tenant_id = TenantId::new();
    let supplied_input = "private-input-material";
    let supplied_key = "private-idempotency-key";
    let invocation = CapabilityInvocation::new(
        capability,
        context(
            principal(Some(tenant_id))?,
            Some(tenant_id),
            RequestId::new(),
            Decision::Allow,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(5),
        )?,
        TenantMode::Tenant,
        json!({"value": supplied_input}),
        ConfirmationEvidence::Confirmed,
        Some(supplied_key.parse()?),
    );
    let rendered = format!("{invocation:?} {:?}", invocation.context());

    assert!(!rendered.contains(supplied_input));
    assert!(!rendered.contains(supplied_key));
    assert!(!rendered.contains("4bf92f3577b34da6a3ce929d0e0e4736"));
    Ok(())
}

fn base_document() -> Result<CapabilityDocument, serde_yaml::Error> {
    serde_yaml::from_str(FIXED_EXAMPLE)
}

fn schema_document() -> Result<CapabilityDocument, Box<dyn Error>> {
    let mut document = base_document()?;
    document.input_schema = ObjectSchema::try_from(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["profile", "tier", "score", "contact"],
        "properties": {
            "profile": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"}
                }
            },
            "tier": {"type": "string", "enum": ["standard", "premium"]},
            "score": {"type": "integer", "minimum": 1, "maximum": 10},
            "contact": {"type": "string", "format": "ipv4"}
        }
    }))?;
    document.output_schema = ObjectSchema::try_from(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["accepted"],
        "properties": {
            "accepted": {"type": "boolean"}
        }
    }))?;
    Ok(document)
}

fn valid_schema_input() -> Value {
    json!({
        "profile": {"name": "Ada"},
        "tier": "standard",
        "score": 5,
        "contact": "192.0.2.1"
    })
}

fn valid_schema_output() -> Value {
    json!({"accepted": true})
}

async fn assert_invalid_schema_input(input: Value) -> Result<(), Box<dyn Error>> {
    let document = schema_document()?;
    let capability = document.key();
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = registry(
        document,
        RuntimeAvailability::Available,
        SchemaHandler {
            calls: Arc::clone(&calls),
            output: valid_schema_output(),
        },
    )?;
    let result = registry
        .invoke(Exposure::Http, invocation_with_input(capability, input)?)
        .await;

    assert!(matches!(result, Err(InvocationError::InputSchemaMismatch)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

fn registry<H>(
    document: CapabilityDocument,
    availability: RuntimeAvailability,
    handler: H,
) -> Result<CapabilityRegistry, RegistryBuildError>
where
    H: CapabilityHandler + 'static,
{
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(document, availability, handler)?;
    Ok(builder.build())
}

fn allowed_invocation(
    capability: omnius_agent_capability_registry::CapabilityKey,
    cancellation: CancellationToken,
) -> Result<CapabilityInvocation, Box<dyn Error>> {
    let tenant_id = TenantId::new();
    Ok(CapabilityInvocation::new(
        capability,
        context(
            principal(Some(tenant_id))?,
            Some(tenant_id),
            RequestId::new(),
            Decision::Allow,
            cancellation,
            OffsetDateTime::now_utc() + time::Duration::seconds(5),
        )?,
        TenantMode::Tenant,
        json!({"query": "allowed"}),
        ConfirmationEvidence::NotProvided,
        None,
    ))
}

fn invocation_with_input(
    capability: omnius_agent_capability_registry::CapabilityKey,
    input: Value,
) -> Result<CapabilityInvocation, Box<dyn Error>> {
    let base = allowed_invocation(capability, CancellationToken::new())?;
    Ok(CapabilityInvocation::new(
        base.capability().clone(),
        base.context().clone(),
        TenantMode::Tenant,
        input,
        ConfirmationEvidence::NotProvided,
        None,
    ))
}

fn context(
    principal: Principal,
    tenant_id: Option<TenantId>,
    request_id: RequestId,
    authorization: Decision,
    cancellation: CancellationToken,
    deadline: OffsetDateTime,
) -> Result<InvocationContext, ContextError> {
    InvocationContext::new(
        request_id,
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .map_err(|_| ContextError::ExpiredDeadline)?,
            None,
        ),
        principal,
        tenant_id,
        authorization,
        "policy.default"
            .parse()
            .map_err(|_| ContextError::ExpiredDeadline)?,
        BudgetBounds::new(1_024, 1_024, 100).map_err(|_| ContextError::ExpiredDeadline)?,
        deadline,
        cancellation,
    )
}

fn principal(tenant_id: Option<TenantId>) -> Result<Principal, omnius_auth_core::PrincipalError> {
    Principal::new(
        SubjectId::new(),
        PrincipalKind::User,
        tenant_id,
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )
}
