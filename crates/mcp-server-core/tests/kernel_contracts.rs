//! Observable contracts for the SDK-free MCP kernel boundary.

use std::{
    error::Error,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityInvocation,
    CapabilityRegistryBuilder, ConfirmationEvidence, Exposure, HandlerError, HandlerInvocation,
    InvocationContext, RuntimeAvailability, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpClientIdentity, McpDispatch, McpDispatchErrorCode,
    McpDispatchRequest, McpKernel, McpPrimitive, McpRequestMetadata,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct RecordingHandler {
    seen: Arc<Mutex<Vec<(RequestId, Exposure)>>>,
}

#[async_trait]
impl CapabilityHandler for RecordingHandler {
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((invocation.context().request_id(), invocation.exposure()));
        Ok(json!({"accepted": true}))
    }
}

#[tokio::test]
async fn repeated_requests_use_fresh_context_and_the_same_shared_registry()
-> Result<(), Box<dyn Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let document = capability_document()?;
    let capability = document.key();
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document,
        RuntimeAvailability::Available,
        RecordingHandler {
            seen: Arc::clone(&seen),
        },
    )?;
    let registry = Arc::new(builder.build());
    let kernel = McpKernel::new(Arc::clone(&registry));
    let first_request = RequestId::new();
    let second_request = RequestId::new();

    assert_eq!(Arc::strong_count(&registry), 2);
    assert_eq!(kernel.protocol_revision(), MCP_PROTOCOL_REVISION);
    assert_eq!(
        kernel.availability_snapshot().capabilities()[0].capability(),
        &capability
    );
    assert_eq!(
        kernel.document(&capability).map(CapabilityDocument::key),
        Some(capability.clone())
    );
    assert_object_safe(&kernel);

    let dispatcher: &dyn McpDispatch = &kernel;
    dispatcher
        .dispatch(dispatch_request(
            McpPrimitive::Tool,
            invocation(capability.clone(), first_request, json!({"request": 1}))?,
        )?)
        .await?;
    dispatcher
        .dispatch(dispatch_request(
            McpPrimitive::Tool,
            invocation(capability, second_request, json!({"request": 2}))?,
        )?)
        .await?;

    assert_eq!(
        *seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [
            (first_request, Exposure::McpTool),
            (second_request, Exposure::McpTool),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn undeclared_projection_is_rejected_before_handler_and_error_is_redacted()
-> Result<(), Box<dyn Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let document = capability_document()?;
    let capability = document.key();
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document,
        RuntimeAvailability::Available,
        RecordingHandler {
            seen: Arc::clone(&seen),
        },
    )?;
    let kernel = McpKernel::new(Arc::new(builder.build()));
    let sensitive_input = "private prompt, provider output, schema, and credential";

    let Err(error) = kernel
        .invoke(dispatch_request(
            McpPrimitive::Resource,
            invocation(
                capability,
                RequestId::new(),
                json!({"secret": sensitive_input}),
            )?,
        )?)
        .await
    else {
        return Err(
            std::io::Error::other("undeclared resource projection unexpectedly succeeded").into(),
        );
    };
    let rendered = format!("{error} {error:?}");

    assert_eq!(error.code(), McpDispatchErrorCode::Rejected);
    assert_eq!(
        rendered,
        "MCP capability dispatch failed McpDispatchError([redacted])"
    );
    assert!(!rendered.contains(sensitive_input));
    assert!(
        seen.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
    Ok(())
}

fn dispatch_request(
    primitive: McpPrimitive,
    invocation: CapabilityInvocation,
) -> Result<McpDispatchRequest, Box<dyn Error>> {
    Ok(McpDispatchRequest::new(
        McpRequestMetadata::new(
            MCP_PROTOCOL_REVISION,
            McpClientIdentity::new("kernel-contract-client", "1.0.0")?,
            ["tools".to_owned()],
            std::iter::empty(),
            None,
        )?,
        primitive,
        invocation,
    ))
}

fn assert_object_safe(_dispatcher: &dyn McpDispatch) {}

fn capability_document() -> Result<CapabilityDocument, serde_json::Error> {
    serde_json::from_value(json!({
        "id": "tests.echo",
        "version": "1.0.0",
        "title": "Echo test input",
        "kind": "query",
        "input_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        },
        "output_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        },
        "permissions": [],
        "side_effect": "none",
        "confirmation": "never",
        "idempotency": "not-applicable",
        "tenant_modes": ["global"],
        "exposures": ["mcp-tool"]
    }))
}

fn invocation(
    capability: omnius_agent_capability_registry::CapabilityKey,
    request_id: RequestId,
    input: Value,
) -> Result<CapabilityInvocation, Box<dyn Error>> {
    Ok(CapabilityInvocation::new(
        capability,
        context(request_id)?,
        TenantMode::Global,
        input,
        ConfirmationEvidence::NotProvided,
        None,
    ))
}

fn context(request_id: RequestId) -> Result<InvocationContext, Box<dyn Error>> {
    let principal = Principal::new(
        SubjectId::new(),
        PrincipalKind::ServiceAccount,
        None,
        AuthMethod::ApiKey,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?;
    Ok(InvocationContext::new(
        request_id,
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal,
        None,
        Decision::Allow,
        "policy.mcp-test".parse()?,
        BudgetBounds::new(4_096, 4_096, 100)?,
        OffsetDateTime::now_utc() + time::Duration::seconds(10),
        CancellationToken::new(),
    )?)
}
