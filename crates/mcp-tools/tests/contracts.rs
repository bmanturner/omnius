//! Focused contracts for canonical MCP tool schemas, catalogs, calls, and results.

use std::{
    collections::BTreeSet,
    error::Error,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityRegistryBuilder,
    ConfirmationEvidence, Exposure, HandlerError, HandlerInvocation, IdempotencyKey,
    InvocationContext, RuntimeAvailability, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_core::RequestId;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtensionCatalog,
    McpRequestContext, McpRequestMetadata,
};
use omnius_mcp_tools::{
    BinaryContent, CanonicalToolResult, CatalogCacheControl, CatalogRevision, CompatibilityState,
    ContentBlock, CurrentResultAdapter, EmbeddedResource, EmbeddedResourceContents,
    EmbeddedResourceUri, InputPrompt, InputRequest, InputRequestId, InputRequiredToolResult,
    JsonSchemaDocument, MAX_REQUIRED_EXTENSIONS, McpContractChange, McpExtension, McpExtensionId,
    McpExtensionRevision, McpKernel, MediaType, RequestState, ResultAdapterError,
    SchemaDocumentError, SchemaRevision, TextContent, ToolAuthorizationDecision,
    ToolAuthorizationOperation, ToolAuthorizationRequest, ToolAuthorizer, ToolCallRequest,
    ToolCatalogError, ToolDeclaration, ToolDeclarationError, ToolDescription, ToolFailureCode,
    ToolName, ToolOutcome, ToolProjection, ToolProtocolError, ToolRepresentation,
    ToolResultAdapter, ToolTitle,
};
use rmcp::model::{CallToolResponse, ServerResult};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[test]
fn schemas_accept_every_json_instance_type_and_boolean_documents() -> Result<(), Box<dyn Error>> {
    let cases = [
        (json!({"type": "null"}), Value::Null),
        (json!({"type": "boolean"}), json!(true)),
        (json!({"type": "number"}), json!(1.25)),
        (json!({"type": "string"}), json!("text")),
        (json!({"type": "array"}), json!([1, 2])),
        (json!({"type": "object"}), json!({"field": 1})),
    ];
    for (schema, instance) in cases {
        JsonSchemaDocument::compile(schema)?.validate(&instance)?;
    }

    JsonSchemaDocument::compile(Value::Bool(true))?.validate(&json!({"any": [null, false]}))?;
    let false_schema = JsonSchemaDocument::compile(Value::Bool(false))?;

    assert!(false_schema.validate(&Value::Null).is_err());
    Ok(())
}

#[test]
fn schemas_allow_local_refs_and_reject_non_local_refs_and_other_dialects()
-> Result<(), Box<dyn Error>> {
    let local = JsonSchemaDocument::compile(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {"identifier": {"type": "integer"}},
        "$ref": "#/$defs/identifier"
    }))?;
    local.validate(&json!(42))?;

    let remote = JsonSchemaDocument::compile(json!({"$ref": "https://example.invalid/schema"}));
    let old_dialect = JsonSchemaDocument::compile(json!({
        "$schema": "http://json-schema.org/draft-07/schema#"
    }));

    assert_eq!(remote, Err(SchemaDocumentError::NonLocalReference));
    assert_eq!(old_dialect, Err(SchemaDocumentError::UnsupportedDialect));
    Ok(())
}
#[expect(
    clippy::too_many_lines,
    reason = "one discovery contract compares every visibility-sensitive list property"
)]
#[tokio::test]
async fn discovery_is_sorted_filtered_and_has_visibility_sensitive_exact_meta()
-> Result<(), Box<dyn Error>> {
    let alpha = capability_document("tests.alpha", "query")?;
    let beta = capability_document("tests.beta", "query")?;
    let preview = capability_document("tests.preview", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([
        (alpha.clone(), json!({}), Arc::clone(&calls)),
        (beta.clone(), json!({}), Arc::clone(&calls)),
        (preview.clone(), json!({}), Arc::clone(&calls)),
    ])?;
    let visible_names = BTreeSet::from([
        ToolName::new("tests.alpha.v1")?,
        ToolName::new("tests.preview.v1")?,
    ]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let authorizer = SelectiveAuthorizer {
        visible_names,
        seen: Arc::clone(&seen),
    };
    let preview_requirement = McpExtension::new(
        McpExtensionId::new("io.omnius/preview")?,
        McpExtensionRevision::new("2026-07-28")?,
    );
    let declarations = vec![
        declaration(
            "tests.preview.v1",
            preview.key(),
            json!({"type": "object"}),
            Value::Bool(true),
            CompatibilityState::Active,
            [preview_requirement.clone()],
        )?,
        declaration(
            "tests.beta.v1",
            beta.key(),
            json!({"type": "object"}),
            Value::Bool(true),
            CompatibilityState::Deprecated {
                since_schema_revision: SchemaRevision::new("schema-1")?,
                change: McpContractChange::Semantic,
                replacement: Some(ToolName::new("tests.alpha.v1")?),
            },
            [],
        )?,
        declaration(
            "tests.alpha.v1",
            alpha.key(),
            json!({"type": "object"}),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?,
    ];
    let projection = ToolProjection::new(
        Arc::clone(&kernel),
        CatalogRevision::new("catalog-17")?,
        CatalogCacheControl::private(10_000)?,
        declarations,
        Arc::new(authorizer),
    )?;

    let baseline_request = request_context()?;
    let baseline = projection.list_tools(&baseline_request).await?;
    let baseline_again = projection.list_tools(&baseline_request).await?;
    let extended_request =
        request_context_with_extensions([preview_requirement.clone()], [preview_requirement])?;
    let extended = projection.list_tools(&extended_request).await?;

    assert_eq!(
        baseline
            .tools()
            .iter()
            .map(|tool| tool.name().as_str())
            .collect::<Vec<_>>(),
        ["tests.alpha.v1"]
    );
    assert_eq!(baseline, baseline_again);
    assert_eq!(
        extended
            .tools()
            .iter()
            .map(|tool| tool.name().as_str())
            .collect::<Vec<_>>(),
        ["tests.alpha.v1", "tests.preview.v1"]
    );
    assert_ne!(
        baseline.meta().catalog_etag().as_str(),
        extended.meta().catalog_etag().as_str()
    );
    assert!(valid_quoted_etag(baseline.meta().catalog_etag().as_str()));

    let encoded = serde_json::to_value(&baseline)?;
    let meta = encoded
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::other("missing _meta"))?;
    assert_eq!(meta.len(), 5);
    assert_eq!(
        meta.get("io.omnius.mcp/catalogRevision"),
        Some(&json!("catalog-17"))
    );
    assert_eq!(
        meta.get("io.omnius.mcp/catalogEtag"),
        Some(&json!(baseline.meta().catalog_etag().as_str()))
    );
    assert_eq!(meta.get("io.omnius.mcp/ttlMs"), Some(&json!(10_000)));
    assert_eq!(
        meta.get("io.omnius.mcp/cacheScope"),
        Some(&json!("private"))
    );
    assert_eq!(
        meta.get("io.omnius.mcp/cacheControl"),
        Some(&json!("private, max-age=10"))
    );
    let authorization_log = seen
        .lock()
        .map_err(|_| io::Error::other("authorization recorder unavailable"))?;
    assert_eq!(
        authorization_log
            .iter()
            .filter(|operation| operation.name == "tests.beta.v1")
            .count(),
        3
    );
    assert_eq!(
        authorization_log
            .iter()
            .filter(|operation| operation.name == "tests.preview.v1")
            .count(),
        1
    );
    assert!(
        authorization_log
            .iter()
            .all(|operation| operation.operation == ToolAuthorizationOperation::Discover)
    );
    Ok(())
}

#[tokio::test]
async fn discovery_omits_wrong_tenant_mode_before_custom_authorization()
-> Result<(), Box<dyn Error>> {
    let document = capability_document_with_tenant_modes("tests.tenant-only", "query", ["tenant"])?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(
        document.clone(),
        json!({"accepted": true}),
        Arc::clone(&calls),
    )])?;
    let name = ToolName::new("tests.tenant-only.v1")?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let projection = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-tenant")?,
        CatalogCacheControl::private(5_000)?,
        [declaration(
            name.as_str(),
            document.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
        Arc::new(SelectiveAuthorizer {
            visible_names: BTreeSet::from([name]),
            seen: Arc::clone(&seen),
        }),
    )?;

    let request = request_context()?;
    let listed = projection.list_tools(&request).await?;

    assert!(listed.tools().is_empty());
    assert!(
        seen.lock()
            .map_err(|_| io::Error::other("authorization recorder unavailable"))?
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn canonical_context_deny_precedes_authorizer_and_schema() -> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.context-deny", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(
        document.clone(),
        json!({"accepted": true}),
        Arc::clone(&calls),
    )])?;
    let name = ToolName::new("tests.context-deny.v1")?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let projection = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-deny")?,
        CatalogCacheControl::private(5_000)?,
        [declaration(
            name.as_str(),
            document.key(),
            json!({"type": "integer"}),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
        Arc::new(SelectiveAuthorizer {
            visible_names: BTreeSet::from([name.clone()]),
            seen: Arc::clone(&seen),
        }),
    )?;
    let denied_request = request_context_with_decision(Decision::Deny(DenyReason::NotEntitled))?;

    let listed = projection.list_tools(&denied_request).await?;
    let called = projection
        .call(ToolCallRequest::new(
            denied_request,
            name,
            json!("schema-oracle-probe"),
            ConfirmationEvidence::NotProvided,
            None,
        ))
        .await;

    assert!(listed.tools().is_empty());
    assert_eq!(called, Err(ToolProtocolError::Rejected));
    assert!(
        seen.lock()
            .map_err(|_| io::Error::other("authorization recorder unavailable"))?
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn extension_negotiation_requires_server_support_and_exact_revision_without_dispatch()
-> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.validation", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(
        document.clone(),
        json!({"accepted": true}),
        Arc::clone(&calls),
    )])?;
    let required = extension("io.omnius/validation", "1")?;
    let projection = projection(
        kernel,
        declaration(
            "tests.validation.v1",
            document.key(),
            json!({"type": "integer"}),
            json!({"type": "object"}),
            CompatibilityState::Active,
            [required.clone()],
        )?,
    )?;

    let unsupported_context = request_context_with_extensions([required.clone()], [])?;
    let unsupported_list = projection.list_tools(&unsupported_context).await?;
    let unsupported_server = projection
        .call(call_request(
            "tests.validation.v1",
            json!(7),
            ConfirmationEvidence::NotProvided,
            None,
            unsupported_context,
        )?)
        .await;

    let wrong_revision_context = request_context_with_extensions(
        [extension("io.omnius/validation", "2")?],
        [required.clone()],
    )?;
    let wrong_revision_list = projection.list_tools(&wrong_revision_context).await?;
    let wrong_revision = projection
        .call(call_request(
            "tests.validation.v1",
            json!(7),
            ConfirmationEvidence::NotProvided,
            None,
            wrong_revision_context,
        )?)
        .await;

    let unknown = projection
        .call(call_request(
            "tests.unknown.v1",
            json!(7),
            ConfirmationEvidence::NotProvided,
            None,
            request_context()?,
        )?)
        .await;
    let exact_context = request_context_with_extensions([required.clone()], [required])?;
    let invalid_input = projection
        .call(call_request(
            "tests.validation.v1",
            json!("not an integer"),
            ConfirmationEvidence::NotProvided,
            None,
            exact_context,
        )?)
        .await;

    assert!(unsupported_list.tools().is_empty());
    assert!(wrong_revision_list.tools().is_empty());
    assert_eq!(unsupported_server, Err(ToolProtocolError::Rejected));
    assert_eq!(wrong_revision, Err(ToolProtocolError::Rejected));
    assert_eq!(unknown, Err(ToolProtocolError::Rejected));
    assert_eq!(invalid_input, Err(ToolProtocolError::InvalidRequest));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn call_authorization_denial_precedes_schema_and_never_dispatches()
-> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.denied", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(
        document.clone(),
        json!({"accepted": true}),
        Arc::clone(&calls),
    )])?;
    let projection = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-1")?,
        CatalogCacheControl::private(5_000)?,
        [declaration(
            "tests.denied.v1",
            document.key(),
            json!({"type": "integer"}),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
        Arc::new(DenyAll),
    )?;

    let denied = projection
        .call(call_request(
            "tests.denied.v1",
            json!("schema-oracle-probe"),
            ConfirmationEvidence::NotProvided,
            None,
            request_context()?,
        )?)
        .await;

    assert_eq!(denied, Err(ToolProtocolError::Rejected));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn valid_call_authorizes_name_then_validated_input_before_kernel()
-> Result<(), Box<dyn Error>> {
    let document = capability_document_with_schemas(
        "tests.two-phase",
        "query",
        &json!({"type": "integer"}),
        &json!({"type": "object"}),
    )?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(
        document.clone(),
        json!({"accepted": true}),
        Arc::clone(&calls),
    )])?;
    let phases = Arc::new(Mutex::new(Vec::new()));
    let projection = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-two-phase")?,
        CatalogCacheControl::private(5_000)?,
        [declaration(
            "tests.two-phase.v1",
            document.key(),
            json!({"type": "integer"}),
            json!({"type": "object"}),
            CompatibilityState::Active,
            [],
        )?],
        Arc::new(PhaseRecordingAuthorizer {
            phases: Arc::clone(&phases),
        }),
    )?;

    let result = projection
        .call(call_request(
            "tests.two-phase.v1",
            json!(7),
            ConfirmationEvidence::NotProvided,
            None,
            request_context()?,
        )?)
        .await?;

    assert!(matches!(
        result,
        CanonicalToolResult::Complete(complete)
            if matches!(complete.outcome(), ToolOutcome::Success { .. })
    ));
    assert_eq!(
        *phases
            .lock()
            .map_err(|_| io::Error::other("phase recorder unavailable"))?,
        [false, true]
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn registry_confirmation_and_idempotency_denials_precede_kernel_handler()
-> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.mutate", "command")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let exposures = Arc::new(Mutex::new(Vec::new()));
    let kernel = kernel_with_recording_exposure(
        document.clone(),
        json!({"changed": true}),
        Arc::clone(&calls),
        Arc::clone(&exposures),
    )?;
    let projection = projection(
        kernel,
        declaration(
            "tests.mutate.v1",
            document.key(),
            json!({"type": "object"}),
            json!({"type": "object", "required": ["changed"]}),
            CompatibilityState::Active,
            [],
        )?,
    )?;

    let missing_both = projection
        .call(call_request(
            "tests.mutate.v1",
            json!({}),
            ConfirmationEvidence::NotProvided,
            None,
            request_context()?,
        )?)
        .await?;
    let missing_key = projection
        .call(call_request(
            "tests.mutate.v1",
            json!({}),
            ConfirmationEvidence::Confirmed,
            None,
            request_context()?,
        )?)
        .await?;
    let key: IdempotencyKey = "mutation-1".parse()?;
    let accepted = projection
        .call(call_request(
            "tests.mutate.v1",
            json!({}),
            ConfirmationEvidence::Confirmed,
            Some(key),
            request_context()?,
        )?)
        .await?;

    assert_eq!(
        failure_code(&missing_both),
        Some(ToolFailureCode::InvalidRequest)
    );
    assert_eq!(
        failure_code(&missing_key),
        Some(ToolFailureCode::InvalidRequest)
    );
    assert!(matches!(
        &accepted,
        CanonicalToolResult::Complete(complete)
            if matches!(complete.outcome(), ToolOutcome::Success { .. })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        *exposures
            .lock()
            .map_err(|_| io::Error::other("exposure recorder unavailable"))?,
        [Exposure::McpTool]
    );
    Ok(())
}

#[tokio::test]
async fn invalid_output_becomes_redacted_internal_error_after_kernel_dispatch()
-> Result<(), Box<dyn Error>> {
    let document =
        capability_document_with_schemas("tests.output", "query", &json!({}), &json!({}))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let sensitive_output = "secret output that must not be rendered";
    let kernel = kernel_with([(
        document.clone(),
        json!(sensitive_output),
        Arc::clone(&calls),
    )])?;
    let projection = projection(
        kernel,
        declaration(
            "tests.output.v1",
            document.key(),
            Value::Bool(true),
            json!({"type": "object"}),
            CompatibilityState::Active,
            [],
        )?,
    )?;

    let result = projection
        .call(call_request(
            "tests.output.v1",
            Value::Null,
            ConfirmationEvidence::NotProvided,
            None,
            request_context()?,
        )?)
        .await?;
    let current = CurrentResultAdapter.adapt(result.clone())?;
    let rendered = format!("{result:?} {}", rmcp_response_json(current)?);

    assert_eq!(failure_code(&result), Some(ToolFailureCode::Internal));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!rendered.contains(sensitive_output));
    Ok(())
}

#[test]
fn complete_result_representations_are_unambiguous_and_bounded() -> Result<(), Box<dyn Error>> {
    let content = vec![
        ContentBlock::Text {
            text: TextContent::new("caller text")?,
        },
        ContentBlock::Image {
            image: BinaryContent::new(MediaType::new("image/png")?, vec![1, 2, 3])?,
        },
        ContentBlock::Audio {
            audio: BinaryContent::new(MediaType::new("audio/wav")?, vec![4, 5])?,
        },
        ContentBlock::EmbeddedResource {
            resource: EmbeddedResource::new(
                EmbeddedResourceUri::new("omnius:records/42")?,
                Some(MediaType::new("text/plain; charset=utf-8")?),
                EmbeddedResourceContents::text(TextContent::new("embedded text")?),
            ),
        },
        ContentBlock::EmbeddedResource {
            resource: EmbeddedResource::new(
                EmbeddedResourceUri::new("omnius:records/43")?,
                Some(MediaType::new("application/octet-stream")?),
                EmbeddedResourceContents::binary(vec![6, 7])?,
            ),
        },
    ];
    let content_only = CanonicalToolResult::success(ToolRepresentation::content_only(content)?);
    let structured_only =
        CanonicalToolResult::success(ToolRepresentation::structured_only(json!([
            null,
            true,
            3,
            "value",
            [],
            {}
        ])));
    let authoritative = CanonicalToolResult::success(ToolRepresentation::authoritative_structured(
        json!({"authoritative": true}),
        vec![ContentBlock::Text {
            text: TextContent::new("supplementary only")?,
        }],
    )?);

    let content_wire = rmcp_response_json(CurrentResultAdapter.adapt(content_only)?)?;
    let structured_wire = rmcp_response_json(CurrentResultAdapter.adapt(structured_only)?)?;
    let authoritative_wire = rmcp_response_json(CurrentResultAdapter.adapt(authoritative)?)?;

    assert_eq!(content_wire.get("resultType"), Some(&json!("complete")));
    assert_eq!(content_wire.get("isError"), Some(&json!(false)));
    assert_eq!(content_wire.get("structuredContent"), None);
    assert_eq!(
        content_wire
            .get("content")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(
        content_wire.pointer("/content/1/data"),
        Some(&json!("AQID"))
    );
    assert_eq!(
        content_wire.pointer("/content/2/data"),
        Some(&json!("BAU="))
    );
    assert_eq!(
        content_wire.pointer("/content/4/resource/blob"),
        Some(&json!("Bgc="))
    );
    assert_eq!(structured_wire.get("resultType"), Some(&json!("complete")));
    assert_eq!(structured_wire.get("content"), Some(&json!([])));
    assert_eq!(
        structured_wire.get("structuredContent"),
        Some(&json!([null, true, 3, "value", [], {}]))
    );
    assert_eq!(structured_wire.get("isError"), Some(&json!(false)));
    assert_eq!(
        authoritative_wire.get("resultType"),
        Some(&json!("complete"))
    );
    assert_eq!(
        authoritative_wire.get("structuredContent"),
        Some(&json!({"authoritative": true}))
    );
    assert_eq!(
        authoritative_wire.pointer("/content/0/text"),
        Some(&json!("supplementary only"))
    );
    assert_eq!(authoritative_wire.get("isError"), Some(&json!(false)));
    Ok(())
}

#[test]
fn complete_error_and_input_required_emit_current_rmcp_wire_shape() -> Result<(), Box<dyn Error>> {
    let complete_error = CanonicalToolResult::error(omnius_mcp_tools::ToolFailure::new(
        ToolFailureCode::Rejected,
    ));
    let request = InputRequest::new(
        InputRequestId::new("approval-code")?,
        InputPrompt::new("Provide the approval code")?,
        JsonSchemaDocument::compile(json!({
            "type": "object",
            "properties": {
                "approval": {"type": "string"}
            },
            "required": ["approval"]
        }))?,
    );
    let input_required = CanonicalToolResult::input_required(InputRequiredToolResult::new(
        vec![request],
        RequestState::new("signed-request-state")?,
    )?);

    let complete = rmcp_response_json(CurrentResultAdapter.adapt(complete_error)?)?;
    let required = rmcp_response_json(CurrentResultAdapter.adapt(input_required)?)?;

    assert_eq!(complete.get("resultType"), Some(&json!("complete")));
    assert_eq!(complete.get("isError"), Some(&json!(true)));
    assert_eq!(
        complete.pointer("/content/0/text"),
        Some(&json!("tool request was rejected"))
    );
    assert_eq!(required.get("resultType"), Some(&json!("input_required")));
    assert_eq!(
        required.get("requestState"),
        Some(&json!("signed-request-state"))
    );
    assert_eq!(
        required.pointer("/inputRequests/approval-code/method"),
        Some(&json!("elicitation/create"))
    );
    assert_eq!(
        required.pointer("/inputRequests/approval-code/params/mode"),
        Some(&json!("form"))
    );
    assert_eq!(
        required.pointer("/inputRequests/approval-code/params/message"),
        Some(&json!("Provide the approval code"))
    );
    assert_eq!(
        required.pointer("/inputRequests/approval-code/params/requestedSchema/type"),
        Some(&json!("object"))
    );
    assert_eq!(
        required.pointer("/inputRequests/approval-code/params/requestedSchema/required"),
        Some(&json!(["approval"]))
    );
    assert_eq!(required.get("content"), None);
    assert_eq!(required.get("isError"), None);
    Ok(())
}

#[test]
fn current_rmcp_adapter_rejects_unrepresentable_input_request_schema() -> Result<(), Box<dyn Error>>
{
    let request = InputRequest::new(
        InputRequestId::new("arbitrary")?,
        InputPrompt::new("Provide arbitrary input")?,
        JsonSchemaDocument::compile(Value::Bool(true))?,
    );
    let result = CanonicalToolResult::input_required(InputRequiredToolResult::new(
        vec![request],
        RequestState::new("signed-request-state")?,
    )?);

    assert!(matches!(
        CurrentResultAdapter.adapt(result),
        Err(ResultAdapterError::UnsupportedInputRequestSchema)
    ));
    Ok(())
}

#[test]
fn current_rmcp_adapter_rejects_lossy_pattern_schema_conversion() -> Result<(), Box<dyn Error>> {
    let request = InputRequest::new(
        InputRequestId::new("patterned-code")?,
        InputPrompt::new("Provide an uppercase approval code")?,
        JsonSchemaDocument::compile(json!({
            "type": "object",
            "properties": {
                "approval": {
                    "type": "string",
                    "pattern": "^[A-Z]+$"
                }
            },
            "required": ["approval"]
        }))?,
    );
    let result = CanonicalToolResult::input_required(InputRequiredToolResult::new(
        vec![request],
        RequestState::new("signed-request-state")?,
    )?);

    assert!(matches!(
        CurrentResultAdapter.adapt(result),
        Err(ResultAdapterError::UnsupportedInputRequestSchema)
    ));
    Ok(())
}

#[test]
fn adapter_trait_allows_future_result_shapes_without_domain_changes() {
    struct VariantOnlyAdapter;

    impl ToolResultAdapter for VariantOnlyAdapter {
        type Output = &'static str;
        type Error = ();

        fn adapt(&self, result: CanonicalToolResult) -> Result<Self::Output, Self::Error> {
            Ok(match result {
                CanonicalToolResult::Complete(_) => "future-complete",
                CanonicalToolResult::InputRequired(_) => "future-input-required",
            })
        }
    }

    let canonical = CanonicalToolResult::success(ToolRepresentation::structured_only(Value::Null));

    assert_eq!(VariantOnlyAdapter.adapt(canonical), Ok("future-complete"));
}

#[test]
fn stable_names_reject_rust_paths_and_unversioned_contracts() {
    assert!(ToolName::new("module::function").is_err());
    assert!(ToolName::new("tests.function").is_err());
    assert!(ToolName::new("tests.function.v1").is_ok());
    assert!(CatalogCacheControl::private(1_500).is_err());
}

#[test]
fn authorization_filtered_catalog_rejects_public_cache_scope() -> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.public-cache", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(document.clone(), json!({}), Arc::clone(&calls))])?;
    let result = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-public")?,
        CatalogCacheControl::public(5_000)?,
        [declaration(
            "tests.public-cache.v1",
            document.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
        Arc::new(AllowAll),
    );

    assert!(matches!(
        result,
        Err(ToolCatalogError::PublicCacheForbidden)
    ));
    Ok(())
}

#[test]
fn extension_requirements_reject_identifier_conflicts_and_fixed_limit_overflow()
-> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.extension-limits", "query")?;
    let input_schema = JsonSchemaDocument::compile(Value::Bool(true))?;
    let output_schema = JsonSchemaDocument::compile(Value::Bool(true))?;
    let duplicate_id = McpExtensionId::new("io.omnius/conflict")?;
    let duplicate = ToolDeclaration::new(
        ToolName::new("tests.extension-limits.v1")?,
        document.key(),
        ToolTitle::new("Extension limits")?,
        None,
        input_schema.clone(),
        output_schema.clone(),
        SchemaRevision::new("schema-1")?,
        CompatibilityState::Active,
        [
            McpExtension::new(duplicate_id.clone(), McpExtensionRevision::new("1")?),
            McpExtension::new(duplicate_id, McpExtensionRevision::new("2")?),
        ],
    );

    let mut excessive_requirements = Vec::new();
    for index in 0..=MAX_REQUIRED_EXTENSIONS {
        excessive_requirements.push(McpExtension::new(
            McpExtensionId::new(format!("io.omnius/required-{index}"))?,
            McpExtensionRevision::new("1")?,
        ));
    }
    let excessive_declaration = ToolDeclaration::new(
        ToolName::new("tests.extension-limits.v2")?,
        document.key(),
        ToolTitle::new("Extension limits")?,
        None,
        input_schema,
        output_schema,
        SchemaRevision::new("schema-2")?,
        CompatibilityState::Active,
        excessive_requirements,
    );

    assert!(matches!(
        duplicate,
        Err(ToolDeclarationError::DuplicateExtension)
    ));
    assert!(matches!(
        excessive_declaration,
        Err(ToolDeclarationError::TooManyExtensions)
    ));
    Ok(())
}

#[tokio::test]
async fn visible_entries_carry_schema_revision_and_deprecation_metadata()
-> Result<(), Box<dyn Error>> {
    let old = capability_document("tests.compat-old", "query")?;
    let current = capability_document("tests.compat-current", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([
        (old.clone(), json!({}), Arc::clone(&calls)),
        (current.clone(), json!({}), Arc::clone(&calls)),
    ])?;
    let current_name = ToolName::new("tests.compat.v2")?;
    let projection = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-compat")?,
        CatalogCacheControl::private(5_000)?,
        [
            declaration(
                "tests.compat.v1",
                old.key(),
                Value::Bool(true),
                Value::Bool(true),
                CompatibilityState::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-1")?,
                    change: McpContractChange::SchemaAndSemantic,
                    replacement: Some(current_name.clone()),
                },
                [],
            )?,
            declaration(
                current_name.as_str(),
                current.key(),
                Value::Bool(true),
                Value::Bool(true),
                CompatibilityState::Active,
                [],
            )?,
        ],
        Arc::new(AllowAll),
    )?;
    let request = request_context()?;
    let listed = projection.list_tools(&request).await?;
    let old_descriptor = listed
        .tools()
        .first()
        .ok_or_else(|| io::Error::other("missing deprecated descriptor"))?;

    assert_eq!(old_descriptor.name().as_str(), "tests.compat.v1");
    assert_eq!(old_descriptor.schema_revision().as_str(), "schema-1");
    assert!(old_descriptor.compatibility().is_deprecated());
    assert_eq!(
        old_descriptor
            .compatibility()
            .replacement()
            .map(ToolName::as_str),
        Some("tests.compat.v2")
    );
    assert_eq!(
        old_descriptor
            .compatibility()
            .since_schema_revision()
            .map(SchemaRevision::as_str),
        Some("schema-1")
    );
    assert_eq!(
        old_descriptor.compatibility().change(),
        Some(McpContractChange::SchemaAndSemantic)
    );
    assert_eq!(
        serde_json::to_value(old_descriptor.compatibility())?,
        json!({
            "status": "deprecated",
            "sinceSchemaRevision": "schema-1",
            "change": "schema_and_semantic",
            "replacement": "tests.compat.v2"
        })
    );
    Ok(())
}

#[test]
fn catalog_successor_accepts_versioned_deprecation_and_removal_after_the_window()
-> Result<(), Box<dyn Error>> {
    let old = capability_document("tests.successor-old", "query")?;
    let current = capability_document("tests.successor-current", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([
        (old.clone(), json!({}), Arc::clone(&calls)),
        (current.clone(), json!({}), Arc::clone(&calls)),
    ])?;
    let before = catalog_projection(
        Arc::clone(&kernel),
        "catalog-before-deprecation",
        [declaration(
            "tests.successor.v1",
            old.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
    )?;
    let during = catalog_projection(
        Arc::clone(&kernel),
        "catalog-during-deprecation",
        [
            declaration(
                "tests.successor.v1",
                old.key(),
                Value::Bool(true),
                Value::Bool(true),
                CompatibilityState::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-2")?,
                    change: McpContractChange::SchemaAndSemantic,
                    replacement: Some(ToolName::new("tests.successor.v2")?),
                },
                [],
            )?,
            declaration_with_schema_revision(
                "tests.successor.v2",
                current.key(),
                Value::Bool(true),
                Value::Bool(true),
                "schema-2",
                CompatibilityState::Active,
                [],
            )?,
        ],
    )?;
    let after = catalog_projection(
        kernel,
        "catalog-after-deprecation",
        [declaration_with_schema_revision(
            "tests.successor.v2",
            current.key(),
            Value::Bool(true),
            Value::Bool(true),
            "schema-2",
            CompatibilityState::Active,
            [],
        )?],
    )?;

    before.catalog().validate_successor(during.catalog())?;
    during.catalog().validate_successor(after.catalog())?;
    Ok(())
}

#[test]
fn catalog_successor_rejects_same_name_schema_and_semantic_mutations() -> Result<(), Box<dyn Error>>
{
    let original = capability_document("tests.immutable", "query")?;
    let changed_semantics = capability_document("tests.immutable", "command")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let original_kernel = kernel_with([(original.clone(), json!({}), Arc::clone(&calls))])?;
    let changed_kernel = kernel_with([(changed_semantics.clone(), json!({}), Arc::clone(&calls))])?;
    let before = catalog_projection(
        Arc::clone(&original_kernel),
        "catalog-immutable-before",
        [declaration(
            "tests.immutable.v1",
            original.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
    )?;
    let schema_changed = catalog_projection(
        original_kernel,
        "catalog-schema-changed",
        [declaration(
            "tests.immutable.v1",
            original.key(),
            json!({"type": "object"}),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
    )?;
    let semantics_changed = catalog_projection(
        changed_kernel,
        "catalog-semantics-changed",
        [declaration(
            "tests.immutable.v1",
            changed_semantics.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
    )?;

    assert_eq!(
        before
            .catalog()
            .validate_successor(schema_changed.catalog()),
        Err(ToolCatalogError::IncompatibleSuccessor)
    );
    assert_eq!(
        before
            .catalog()
            .validate_successor(semantics_changed.catalog()),
        Err(ToolCatalogError::IncompatibleSuccessor)
    );
    Ok(())
}

#[test]
fn catalog_successor_rejects_active_name_removal() -> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.active-removal", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(document.clone(), json!({}), calls)])?;
    let before = catalog_projection(
        Arc::clone(&kernel),
        "catalog-active-before",
        [declaration(
            "tests.active-removal.v1",
            document.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
    )?;
    let after = catalog_projection(
        kernel,
        "catalog-active-after",
        Vec::<ToolDeclaration>::new(),
    )?;

    assert_eq!(
        before.catalog().validate_successor(after.catalog()),
        Err(ToolCatalogError::IncompatibleSuccessor)
    );
    Ok(())
}

#[test]
fn catalog_successor_rejects_deprecated_reactivation_or_window_mutation()
-> Result<(), Box<dyn Error>> {
    let document = capability_document("tests.deprecated-transition", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([(document.clone(), json!({}), calls)])?;
    let before = catalog_projection(
        Arc::clone(&kernel),
        "catalog-deprecated-before",
        [declaration(
            "tests.deprecated-transition.v1",
            document.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Deprecated {
                since_schema_revision: SchemaRevision::new("schema-1")?,
                change: McpContractChange::Semantic,
                replacement: None,
            },
            [],
        )?],
    )?;
    let reactivated = catalog_projection(
        Arc::clone(&kernel),
        "catalog-deprecated-reactivated",
        [declaration(
            "tests.deprecated-transition.v1",
            document.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Active,
            [],
        )?],
    )?;
    let changed_window = catalog_projection(
        kernel,
        "catalog-deprecated-window-changed",
        [declaration(
            "tests.deprecated-transition.v1",
            document.key(),
            Value::Bool(true),
            Value::Bool(true),
            CompatibilityState::Deprecated {
                since_schema_revision: SchemaRevision::new("schema-2")?,
                change: McpContractChange::Schema,
                replacement: None,
            },
            [],
        )?],
    )?;

    assert_eq!(
        before.catalog().validate_successor(reactivated.catalog()),
        Err(ToolCatalogError::IncompatibleSuccessor)
    );
    assert_eq!(
        before
            .catalog()
            .validate_successor(changed_window.catalog()),
        Err(ToolCatalogError::IncompatibleSuccessor)
    );
    Ok(())
}

#[tokio::test]
async fn deprecated_replacement_is_omitted_when_target_is_authorization_hidden()
-> Result<(), Box<dyn Error>> {
    let old = capability_document("tests.hidden-target-old", "query")?;
    let target = capability_document("tests.hidden-target-current", "query")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = kernel_with([
        (old.clone(), json!({}), Arc::clone(&calls)),
        (target.clone(), json!({}), Arc::clone(&calls)),
    ])?;
    let old_name = ToolName::new("tests.hidden-target.v1")?;
    let target_name = ToolName::new("tests.hidden-target.v2")?;
    let projection = ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-hidden-target")?,
        CatalogCacheControl::private(5_000)?,
        [
            declaration(
                old_name.as_str(),
                old.key(),
                Value::Bool(true),
                Value::Bool(true),
                CompatibilityState::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-1")?,
                    change: McpContractChange::Semantic,
                    replacement: Some(target_name.clone()),
                },
                [],
            )?,
            declaration(
                target_name.as_str(),
                target.key(),
                Value::Bool(true),
                Value::Bool(true),
                CompatibilityState::Active,
                [],
            )?,
        ],
        Arc::new(SelectiveAuthorizer {
            visible_names: BTreeSet::from([old_name]),
            seen: Arc::new(Mutex::new(Vec::new())),
        }),
    )?;
    let request = request_context()?;
    let listed = projection.list_tools(&request).await?;
    let descriptor = listed
        .tools()
        .first()
        .ok_or_else(|| io::Error::other("missing deprecated descriptor"))?;

    assert_eq!(listed.tools().len(), 1);
    assert!(descriptor.compatibility().is_deprecated());
    assert_eq!(descriptor.compatibility().replacement(), None);
    assert_eq!(
        serde_json::to_value(descriptor.compatibility())?,
        json!({
            "status": "deprecated",
            "sinceSchemaRevision": "schema-1",
            "change": "semantic"
        })
    );
    Ok(())
}

#[derive(Clone)]
struct RecordingHandler {
    calls: Arc<AtomicUsize>,
    output: Value,
    exposures: Option<Arc<Mutex<Vec<Exposure>>>>,
}

#[async_trait]
impl CapabilityHandler for RecordingHandler {
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(exposures) = &self.exposures {
            exposures
                .lock()
                .map_err(|_| {
                    HandlerError::new(omnius_agent_capability_registry::HandlerErrorCode::Internal)
                })?
                .push(invocation.exposure());
        }
        Ok(self.output.clone())
    }
}

#[derive(Clone)]
struct SeenAuthorization {
    name: String,
    operation: ToolAuthorizationOperation,
}

struct SelectiveAuthorizer {
    visible_names: BTreeSet<ToolName>,
    seen: Arc<Mutex<Vec<SeenAuthorization>>>,
}

#[async_trait]
impl ToolAuthorizer for SelectiveAuthorizer {
    async fn authorize(&self, request: ToolAuthorizationRequest<'_>) -> ToolAuthorizationDecision {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(SeenAuthorization {
                name: request.declaration().name().as_str().to_owned(),
                operation: request.operation(),
            });
        }
        if self.visible_names.contains(request.declaration().name()) {
            ToolAuthorizationDecision::Allow
        } else {
            ToolAuthorizationDecision::Deny
        }
    }
}

struct PhaseRecordingAuthorizer {
    phases: Arc<Mutex<Vec<bool>>>,
}

#[async_trait]
impl ToolAuthorizer for PhaseRecordingAuthorizer {
    async fn authorize(&self, request: ToolAuthorizationRequest<'_>) -> ToolAuthorizationDecision {
        if let Ok(mut phases) = self.phases.lock() {
            phases.push(request.input().is_some());
        }
        ToolAuthorizationDecision::Allow
    }
}

struct AllowAll;

#[async_trait]
impl ToolAuthorizer for AllowAll {
    async fn authorize(&self, _request: ToolAuthorizationRequest<'_>) -> ToolAuthorizationDecision {
        ToolAuthorizationDecision::Allow
    }
}

struct DenyAll;

#[async_trait]
impl ToolAuthorizer for DenyAll {
    async fn authorize(&self, _request: ToolAuthorizationRequest<'_>) -> ToolAuthorizationDecision {
        ToolAuthorizationDecision::Deny
    }
}

fn kernel_with<const N: usize>(
    entries: [(CapabilityDocument, Value, Arc<AtomicUsize>); N],
) -> Result<Arc<McpKernel>, Box<dyn Error>> {
    let mut builder = CapabilityRegistryBuilder::new();
    for (document, output, calls) in entries {
        builder.register(
            document,
            RuntimeAvailability::Available,
            RecordingHandler {
                calls,
                output,
                exposures: None,
            },
        )?;
    }
    Ok(Arc::new(McpKernel::new(Arc::new(builder.build()))))
}

fn kernel_with_recording_exposure(
    document: CapabilityDocument,
    output: Value,
    calls: Arc<AtomicUsize>,
    exposures: Arc<Mutex<Vec<Exposure>>>,
) -> Result<Arc<McpKernel>, Box<dyn Error>> {
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document,
        RuntimeAvailability::Available,
        RecordingHandler {
            calls,
            output,
            exposures: Some(exposures),
        },
    )?;
    Ok(Arc::new(McpKernel::new(Arc::new(builder.build()))))
}

fn catalog_projection(
    kernel: Arc<McpKernel>,
    revision: &str,
    declarations: impl IntoIterator<Item = ToolDeclaration>,
) -> Result<ToolProjection, Box<dyn Error>> {
    Ok(ToolProjection::new(
        kernel,
        CatalogRevision::new(revision)?,
        CatalogCacheControl::private(5_000)?,
        declarations,
        Arc::new(AllowAll),
    )?)
}

fn projection(
    kernel: Arc<McpKernel>,
    declaration: ToolDeclaration,
) -> Result<ToolProjection, Box<dyn Error>> {
    Ok(ToolProjection::new(
        kernel,
        CatalogRevision::new("catalog-1")?,
        CatalogCacheControl::private(5_000)?,
        [declaration],
        Arc::new(AllowAll),
    )?)
}

fn declaration<const N: usize>(
    name: &str,
    capability: omnius_agent_capability_registry::CapabilityKey,
    input_schema: Value,
    output_schema: Value,
    compatibility: CompatibilityState,
    required_extensions: [McpExtension; N],
) -> Result<ToolDeclaration, Box<dyn Error>> {
    declaration_with_schema_revision(
        name,
        capability,
        input_schema,
        output_schema,
        "schema-1",
        compatibility,
        required_extensions,
    )
}

fn declaration_with_schema_revision<const N: usize>(
    name: &str,
    capability: omnius_agent_capability_registry::CapabilityKey,
    input_schema: Value,
    output_schema: Value,
    schema_revision: &str,
    compatibility: CompatibilityState,
    required_extensions: [McpExtension; N],
) -> Result<ToolDeclaration, Box<dyn Error>> {
    Ok(ToolDeclaration::new(
        ToolName::new(name)?,
        capability,
        ToolTitle::new("Contract tool")?,
        Some(ToolDescription::new("A contract-test public description")?),
        JsonSchemaDocument::compile(input_schema)?,
        JsonSchemaDocument::compile(output_schema)?,
        SchemaRevision::new(schema_revision)?,
        compatibility,
        required_extensions,
    )?)
}

fn call_request(
    name: &str,
    input: Value,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
    request_context: McpRequestContext,
) -> Result<ToolCallRequest, Box<dyn Error>> {
    Ok(ToolCallRequest::new(
        request_context,
        ToolName::new(name)?,
        input,
        confirmation,
        idempotency_key,
    ))
}

fn capability_document(id: &str, kind: &str) -> Result<CapabilityDocument, serde_json::Error> {
    capability_document_with_tenant_modes(id, kind, ["global"])
}

fn capability_document_with_schemas(
    id: &str,
    kind: &str,
    input_schema: &Value,
    output_schema: &Value,
) -> Result<CapabilityDocument, serde_json::Error> {
    capability_document_with_schemas_and_tenant_modes(
        id,
        kind,
        input_schema,
        output_schema,
        ["global"],
    )
}

fn capability_document_with_tenant_modes<const N: usize>(
    id: &str,
    kind: &str,
    tenant_modes: [&str; N],
) -> Result<CapabilityDocument, serde_json::Error> {
    capability_document_with_schemas_and_tenant_modes(
        id,
        kind,
        &json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        }),
        &json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        }),
        tenant_modes,
    )
}

fn capability_document_with_schemas_and_tenant_modes<const N: usize>(
    id: &str,
    kind: &str,
    input_schema: &Value,
    output_schema: &Value,
    tenant_modes: [&str; N],
) -> Result<CapabilityDocument, serde_json::Error> {
    let (side_effect, confirmation, idempotency) = if kind == "command" {
        ("mutating", "always", "required")
    } else {
        ("none", "never", "not-applicable")
    };
    serde_json::from_value(json!({
        "id": id,
        "version": "1.0.0",
        "title": "MCP contract capability",
        "kind": kind,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "permissions": [],
        "side_effect": side_effect,
        "confirmation": confirmation,
        "idempotency": idempotency,
        "tenant_modes": tenant_modes.as_slice(),
        "exposures": ["mcp-tool"]
    }))
}

fn extension(id: &str, revision: &str) -> Result<McpExtension, Box<dyn Error>> {
    Ok(McpExtension::new(
        McpExtensionId::new(id)?,
        McpExtensionRevision::new(revision)?,
    ))
}

fn request_context() -> Result<McpRequestContext, Box<dyn Error>> {
    request_context_with_extensions([], [])
}

fn request_context_with_decision(decision: Decision) -> Result<McpRequestContext, Box<dyn Error>> {
    build_request_context(decision, [], [])
}

fn request_context_with_extensions<const R: usize, const S: usize>(
    requested: [McpExtension; R],
    supported: [McpExtension; S],
) -> Result<McpRequestContext, Box<dyn Error>> {
    build_request_context(Decision::Allow, requested, supported)
}

fn build_request_context<const R: usize, const S: usize>(
    decision: Decision,
    requested: [McpExtension; R],
    supported: [McpExtension; S],
) -> Result<McpRequestContext, Box<dyn Error>> {
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("mcp-tools-tests", "1")?,
        Vec::new(),
        requested,
        None,
    )?;
    let extension_catalog = McpExtensionCatalog::new(supported)?;
    let canonical = McpCanonicalContext::new(context_with_decision(decision)?, TenantMode::Global)?;
    Ok(McpRequestContext::new(
        metadata,
        &extension_catalog,
        canonical,
    ))
}

fn context_with_decision(decision: Decision) -> Result<InvocationContext, Box<dyn Error>> {
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
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal,
        None,
        decision,
        "policy.mcp-tools".parse()?,
        BudgetBounds::new(32_768, 32_768, 1_000)?,
        OffsetDateTime::now_utc() + time::Duration::seconds(30),
        CancellationToken::new(),
    )?)
}

fn rmcp_response_json(response: CallToolResponse) -> Result<Value, serde_json::Error> {
    serde_json::to_value(ServerResult::from(response))
}

fn failure_code(result: &CanonicalToolResult) -> Option<ToolFailureCode> {
    match result {
        CanonicalToolResult::Complete(complete) => match complete.outcome() {
            ToolOutcome::Success { .. } => None,
            ToolOutcome::Error { error } => Some(error.code()),
        },
        CanonicalToolResult::InputRequired(_) => None,
    }
}

fn valid_quoted_etag(value: &str) -> bool {
    value.len() == 73
        && value.starts_with("\"sha256:")
        && value.ends_with('"')
        && value[8..72]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
