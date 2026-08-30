//! Contracts for canonical request mapping, extension negotiation, and exposure filtering.

use std::{error::Error, sync::Arc};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityRegistryBuilder, HandlerError,
    HandlerInvocation, InvocationContext, RuntimeAvailability, TenantMode, TraceContext,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_core::RequestId;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExposureAuthorizer,
    McpExposureFilter, McpExtensionCatalog, McpExtensionId, McpKernel, McpPrimitive,
    McpRequestContext, McpRequestContextError, McpRequestMetadata,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
struct EmptyHandler;

#[async_trait]
impl CapabilityHandler for EmptyHandler {
    async fn invoke(&self, _invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        Ok(json!({}))
    }
}

#[derive(Debug)]
struct ScopeAuthorizer;

impl McpExposureAuthorizer for ScopeAuthorizer {
    fn is_authorized(
        &self,
        request: &McpRequestContext,
        document: &CapabilityDocument,
        _primitive: McpPrimitive,
    ) -> bool {
        document.permissions.iter().all(|permission| {
            request
                .canonical()
                .invocation()
                .principal()
                .scopes
                .iter()
                .any(|scope| scope.as_str() == permission.as_str())
        })
    }
}

#[test]
fn extensions_activate_only_for_exact_client_and_server_support() -> Result<(), Box<dyn Error>> {
    let tasks = McpExtensionId::new("io.modelcontextprotocol/tasks")?;
    let apps = McpExtensionId::new("io.modelcontextprotocol/apps")?;
    let catalog = McpExtensionCatalog::new([tasks.clone(), apps.clone()])?;
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("contract-client", "1.0.0")?,
        std::iter::empty(),
        [
            "io.modelcontextprotocol/tasks".to_owned(),
            "io.example/unsupported".to_owned(),
            "logging".to_owned(),
        ],
        None,
    )?;
    let request = McpRequestContext::new(metadata, &catalog, canonical(Decision::Allow)?);

    assert!(request.negotiated_extensions().contains(&tasks));
    assert!(!request.negotiated_extensions().contains(&apps));
    assert_eq!(request.negotiated_extensions().extensions().len(), 1);
    assert!(
        request
            .metadata()
            .requested_extensions()
            .contains("io.example/unsupported")
    );
    assert!(
        request
            .metadata()
            .requested_extensions()
            .contains("logging")
    );
    Ok(())
}

#[test]
fn deprecated_surfaces_cannot_enter_the_extension_catalog() {
    for identifier in [
        "roots",
        "sampling",
        "logging",
        "http-sse",
        "io.modelcontextprotocol/roots",
        "io.modelcontextprotocol/sampling",
        "io.modelcontextprotocol/logging",
        "io.modelcontextprotocol/http+sse",
    ] {
        assert!(McpExtensionId::new(identifier).is_err());
    }
}

#[test]
fn discovery_filters_availability_projection_tenant_principal_and_authorization()
-> Result<(), Box<dyn Error>> {
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(
        document("visible", &["mcp:read"], &["global"], &["mcp-tool"])?,
        RuntimeAvailability::Available,
        EmptyHandler,
    )?;
    builder.register(
        document("missing-scope", &["mcp:admin"], &["global"], &["mcp-tool"])?,
        RuntimeAvailability::Available,
        EmptyHandler,
    )?;
    builder.register(
        document("wrong-tenant", &["mcp:read"], &["tenant"], &["mcp-tool"])?,
        RuntimeAvailability::Available,
        EmptyHandler,
    )?;
    builder.register(
        document(
            "wrong-primitive",
            &["mcp:read"],
            &["global"],
            &["mcp-prompt"],
        )?,
        RuntimeAvailability::Available,
        EmptyHandler,
    )?;
    let unavailable = document("unavailable", &["mcp:read"], &["global"], &["mcp-tool"])?;
    builder.register(
        unavailable,
        RuntimeAvailability::Unavailable(
            omnius_agent_capability_registry::AvailabilityReason::DependencyUnavailable,
        ),
        EmptyHandler,
    )?;

    let kernel = McpKernel::new(Arc::new(builder.build()));
    let filter = McpExposureFilter::new(kernel, Arc::new(ScopeAuthorizer));
    let request = request_context(Decision::Allow)?;
    let authorized = filter.authorized(&request, McpPrimitive::Tool);

    assert_eq!(authorized.documents().len(), 1);
    assert_eq!(authorized.documents()[0].id.as_str(), "tests.visible");

    let denied = request_context(Decision::Deny(DenyReason::NotEntitled))?;
    assert!(
        filter
            .authorized(&denied, McpPrimitive::Tool)
            .documents()
            .is_empty()
    );
    Ok(())
}

#[test]
fn tenant_mode_must_match_the_authenticated_tenant() -> Result<(), Box<dyn Error>> {
    let global = invocation_context(Decision::Allow)?;
    assert!(matches!(
        McpCanonicalContext::new(global, TenantMode::Tenant),
        Err(McpRequestContextError::TenantContextMismatch)
    ));

    let tenant = invocation_context_for_tenant(Decision::Allow, Some(TenantId::new()))?;
    assert!(matches!(
        McpCanonicalContext::new(tenant, TenantMode::Global),
        Err(McpRequestContextError::TenantContextMismatch)
    ));
    Ok(())
}

fn request_context(decision: Decision) -> Result<McpRequestContext, Box<dyn Error>> {
    Ok(McpRequestContext::new(
        metadata()?,
        &McpExtensionCatalog::empty(),
        canonical(decision)?,
    ))
}

fn canonical(decision: Decision) -> Result<McpCanonicalContext, Box<dyn Error>> {
    Ok(McpCanonicalContext::new(
        invocation_context(decision)?,
        TenantMode::Global,
    )?)
}

fn invocation_context(decision: Decision) -> Result<InvocationContext, Box<dyn Error>> {
    invocation_context_for_tenant(decision, None)
}

fn invocation_context_for_tenant(
    decision: Decision,
    tenant_id: Option<TenantId>,
) -> Result<InvocationContext, Box<dyn Error>> {
    let principal = Principal::new(
        SubjectId::new(),
        PrincipalKind::ServiceAccount,
        tenant_id,
        AuthMethod::ApiKey,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        vec![Scope::new("mcp:read")?],
    )?;
    Ok(InvocationContext::new(
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal,
        tenant_id,
        decision,
        "policy.mcp-discovery".parse()?,
        BudgetBounds::new(4_096, 4_096, 100)?,
        OffsetDateTime::now_utc() + time::Duration::seconds(10),
        CancellationToken::new(),
    )?)
}

fn metadata() -> Result<McpRequestMetadata, Box<dyn Error>> {
    Ok(McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("discovery-client", "1.0.0")?,
        ["tools".to_owned()],
        std::iter::empty(),
        None,
    )?)
}

fn document(
    id: &str,
    permissions: &[&str],
    tenant_modes: &[&str],
    exposures: &[&str],
) -> Result<CapabilityDocument, serde_json::Error> {
    serde_json::from_value(json!({
        "id": format!("tests.{id}"),
        "version": "1.0.0",
        "title": format!("{id} contract"),
        "kind": "query",
        "input_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        },
        "output_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        },
        "permissions": permissions,
        "side_effect": "none",
        "confirmation": "never",
        "idempotency": "not-applicable",
        "tenant_modes": tenant_modes,
        "exposures": exposures
    }))
}
