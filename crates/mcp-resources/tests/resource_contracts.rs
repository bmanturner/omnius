//! Behavioral contracts for authorization-aware MCP resource projection.
#![expect(
    clippy::expect_used,
    reason = "contract assertions use invariant-specific failure messages"
)]

use std::{
    collections::{BTreeSet, VecDeque},
    error::Error,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use omnius_agent_capability_registry::{
    AvailabilityReason, BudgetBounds, CapabilityDocument, CapabilityHandler, CapabilityKey,
    CapabilityRegistryBuilder, ConfirmationEvidence, Exposure, HandlerError, HandlerInvocation,
    InvocationContext, RuntimeAvailability, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_core::RequestId;
use omnius_mcp_resources::{
    ByteRange, CacheControl, CacheScope, CatalogRevision, ExactResourceDeclaration, MimeType,
    PublicResourceName, ResourceAuthorizer, ResourceCatalog, ResourceCompatibility,
    ResourceErrorCode, ResourceLimits, ResourceMetadata, ResourceOperation, ResourceProjection,
    ResourceRequest, ResourceTemplateDeclaration, ResourceTitle, ResourceUri, ResourceUriTemplate,
    SchemaRevision, TemplateVariableName, TenantBinding,
};
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpContractChange, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpKernel, McpRequestContext,
    McpRequestMetadata,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
type RecordedInvocations = Arc<Mutex<Vec<(Exposure, Value)>>>;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone)]
struct RecordingHandler {
    outputs: Arc<Mutex<VecDeque<Value>>>,
    invocations: RecordedInvocations,
}

#[async_trait]
impl CapabilityHandler for RecordingHandler {
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        self.invocations
            .lock()
            .expect("invocation recording lock")
            .push((invocation.exposure(), invocation.input().clone()));
        Ok(self
            .outputs
            .lock()
            .expect("output queue lock")
            .pop_front()
            .expect("queued canonical result"))
    }
}

struct AllowAll;

#[async_trait]
impl ResourceAuthorizer for AllowAll {
    async fn authorize(
        &self,
        _context: &InvocationContext,
        _action: omnius_mcp_resources::ResourceAuthorizationAction,
        _target: omnius_mcp_resources::ResourceAuthorizationTarget<'_>,
    ) -> Decision {
        Decision::Allow
    }
}

struct NamedAuthorizer {
    allowed: BTreeSet<String>,
}

#[async_trait]
impl ResourceAuthorizer for NamedAuthorizer {
    async fn authorize(
        &self,
        _context: &InvocationContext,
        _action: omnius_mcp_resources::ResourceAuthorizationAction,
        target: omnius_mcp_resources::ResourceAuthorizationTarget<'_>,
    ) -> Decision {
        if self.allowed.contains(target.name().as_str()) {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::NotEntitled)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one discovery contract checks every visibility-sensitive list property"
)]
#[tokio::test]
async fn authorized_lists_are_deterministic_separate_and_exact_extension_filtered()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let extension = exact_extension("io.omnius.resource/rich", "v1")?;
    let other_revision = exact_extension("io.omnius.resource/rich", "v2")?;
    let extended_uri = ResourceUri::parse("omnius://catalog/extended".to_owned())?;
    let exact = vec![
        exact_declaration(
            "zulu@v1",
            "omnius://catalog/zulu",
            capability.clone(),
            BTreeSet::new(),
        )?,
        exact_declaration(
            "alpha@v1",
            "omnius://catalog/alpha",
            capability.clone(),
            BTreeSet::new(),
        )?,
        deprecated_exact_declaration(
            "old@v1",
            "omnius://catalog/old",
            "alpha@v1",
            capability.clone(),
        )?,
        exact_declaration(
            "extended@v1",
            extended_uri.as_str(),
            capability.clone(),
            BTreeSet::from([extension.clone()]),
        )?,
    ];
    let templates = vec![template_declaration(
        "items@v1",
        "omnius://catalog/items/{item_id}",
        capability,
        TenantMode::Global,
        TenantBinding::Global,
        BTreeSet::new(),
        1_024,
    )?];
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("catalog-17".to_owned())?,
        CacheControl::private(60)?,
        exact,
        templates,
    )?);
    let allowed = BTreeSet::from([
        "alpha@v1".to_owned(),
        "old@v1".to_owned(),
        "extended@v1".to_owned(),
        "items@v1".to_owned(),
    ]);
    let extended_output = canonical_output(
        extended_uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "rich"}),
        b"rich",
        None,
        None,
    );
    let (projection, invocations) = projection(
        catalog,
        Arc::new(NamedAuthorizer { allowed }),
        vec![extended_output],
    )?;
    let allowed_invocation = context(None, Decision::Allow)?;
    let baseline_request = request_context(
        allowed_invocation.clone(),
        TenantMode::Global,
        Vec::new(),
        Vec::new(),
    )?;
    let extended_request = request_context(
        allowed_invocation.clone(),
        TenantMode::Global,
        vec![extension.clone()],
        vec![extension.clone()],
    )?;
    let client_revision_mismatch = request_context(
        allowed_invocation.clone(),
        TenantMode::Global,
        vec![other_revision.clone()],
        vec![extension.clone()],
    )?;
    let server_revision_mismatch = request_context(
        allowed_invocation,
        TenantMode::Global,
        vec![extension.clone()],
        vec![other_revision],
    )?;
    let denied_request = baseline_request_context(
        context(None, Decision::Deny(DenyReason::TenantMismatch))?,
        TenantMode::Global,
    )?;

    let baseline = projection.list_authorized(&baseline_request).await?;
    let repeated = projection.list_authorized(&baseline_request).await?;
    let extended = projection.list_authorized(&extended_request).await?;
    let client_mismatch = projection
        .list_authorized(&client_revision_mismatch)
        .await?;
    let server_mismatch = projection
        .list_authorized(&server_revision_mismatch)
        .await?;
    let denied = projection.list_authorized(&denied_request).await?;

    assert_eq!(
        baseline
            .resources()
            .iter()
            .map(|resource| resource.name().as_str())
            .collect::<Vec<_>>(),
        ["alpha@v1", "old@v1"]
    );
    assert_eq!(baseline.templates()[0].name().as_str(), "items@v1");
    assert!(
        extended
            .resources()
            .iter()
            .any(|resource| resource.name().as_str() == "extended@v1")
    );
    assert_eq!(
        client_mismatch.metadata().catalog_etag(),
        baseline.metadata().catalog_etag()
    );
    assert_eq!(
        server_mismatch.metadata().catalog_etag(),
        baseline.metadata().catalog_etag()
    );
    assert!(matches!(
        baseline.resources()[1].compatibility(),
        ResourceCompatibility::Deprecated {
            since_schema_revision,
            change: McpContractChange::Semantic,
            replacement: Some(replacement),
        } if since_schema_revision.as_str() == "schema-2"
            && replacement.as_str() == "alpha@v1"
    ));
    assert_eq!(
        baseline.metadata().catalog_etag(),
        repeated.metadata().catalog_etag()
    );
    assert_ne!(
        baseline.metadata().catalog_etag(),
        extended.metadata().catalog_etag()
    );
    assert_ne!(
        baseline.metadata().catalog_etag(),
        denied.metadata().catalog_etag()
    );
    assert!(denied.resources().is_empty());
    assert!(denied.templates().is_empty());
    let adapter_meta = baseline.metadata().adapter_meta();
    assert_eq!(adapter_meta["io.omnius.mcp/ttlMs"], json!(60_000));
    assert_eq!(
        adapter_meta["io.omnius.mcp/cacheControl"],
        json!("private, max-age=60")
    );
    assert_eq!(adapter_meta.len(), 5);
    assert_eq!(
        adapter_meta["io.omnius.mcp/catalogRevision"],
        json!("catalog-17")
    );
    assert_eq!(adapter_meta["io.omnius.mcp/cacheScope"], json!("private"));
    assert!(
        adapter_meta["io.omnius.mcp/catalogEtag"]
            .as_str()
            .is_some_and(|etag| etag.starts_with("\"sha256:") && etag.ends_with('"'))
    );

    let baseline_read = read_request_with_context(
        PublicResourceName::new("extended@v1".to_owned())?,
        extended_uri.clone(),
        None,
        baseline_request,
    )?;
    assert_eq!(
        projection
            .read(baseline_read)
            .await
            .expect_err("unnegotiated extension read")
            .code(),
        ResourceErrorCode::Rejected
    );
    let exact_match = read_request_with_context(
        PublicResourceName::new("extended@v1".to_owned())?,
        extended_uri.clone(),
        None,
        extended_request,
    )?;
    assert_eq!(
        projection.read(exact_match).await?.content().as_text(),
        Some("rich")
    );
    for mismatched_request in [client_revision_mismatch, server_revision_mismatch] {
        let request = read_request_with_context(
            PublicResourceName::new("extended@v1".to_owned())?,
            extended_uri.clone(),
            None,
            mismatched_request,
        )?;
        assert_eq!(
            projection
                .read(request)
                .await
                .expect_err("extension revision mismatch")
                .code(),
            ResourceErrorCode::Rejected
        );
    }
    let seen = invocations.lock().expect("invocation recording lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].1["required_extensions"],
        json!([{"id": "io.omnius.resource/rich", "revision": "v1"}])
    );
    assert_eq!(
        seen[0].1["negotiated_extensions"],
        json!([{"id": "io.omnius.resource/rich", "revision": "v1"}])
    );
    Ok(())
}

#[tokio::test]
async fn unavailable_capabilities_are_omitted_from_discovery() -> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("availability-1".to_owned())?,
        CacheControl::private(30)?,
        vec![exact_declaration(
            "alpha@v1",
            "omnius://catalog/alpha",
            capability,
            BTreeSet::new(),
        )?],
        Vec::new(),
    )?);
    let (projection, _) = projection_with_availability(
        catalog,
        Arc::new(AllowAll),
        Vec::new(),
        RuntimeAvailability::Unavailable(AvailabilityReason::Unhealthy),
    )?;

    let request = baseline_request_context(context(None, Decision::Allow)?, TenantMode::Global)?;
    let visible = projection.list_authorized(&request).await?;

    assert!(visible.resources().is_empty());
    assert!(visible.templates().is_empty());
    Ok(())
}

#[tokio::test]
async fn discovery_uses_the_selected_canonical_tenant_mode() -> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("tenant-parity-1".to_owned())?,
        CacheControl::private(30)?,
        vec![exact_declaration(
            "global@v1",
            "omnius://catalog/global",
            capability.clone(),
            BTreeSet::new(),
        )?],
        vec![template_declaration(
            "tenant@v1",
            "omnius://catalog/tenants/{tenant_id}/items/{item_id}",
            capability,
            TenantMode::Tenant,
            TenantBinding::PathVariable(TemplateVariableName::new("tenant_id".to_owned())?),
            BTreeSet::new(),
            1_024,
        )?],
    )?);
    let (projection, _) = projection(catalog, Arc::new(AllowAll), Vec::new())?;
    let tenant = TenantId::new();
    let global_request =
        baseline_request_context(context(None, Decision::Allow)?, TenantMode::Global)?;
    let tenant_invocation = context(Some(tenant), Decision::Allow)?;
    let tenant_request = baseline_request_context(tenant_invocation.clone(), TenantMode::Tenant)?;
    let wrong_mode_request = baseline_request_context(tenant_invocation, TenantMode::Principal)?;

    let global_view = projection.list_authorized(&global_request).await?;
    let tenant_view = projection.list_authorized(&tenant_request).await?;
    let wrong_mode_view = projection.list_authorized(&wrong_mode_request).await?;

    assert_eq!(global_view.resources().len(), 1);
    assert!(global_view.templates().is_empty());
    assert!(tenant_view.resources().is_empty());
    assert_eq!(tenant_view.templates().len(), 1);
    assert!(wrong_mode_view.resources().is_empty());
    assert!(wrong_mode_view.templates().is_empty());
    Ok(())
}

#[test]
fn byte_range_rejects_unrepresentable_final_index_before_request() -> Result<(), Box<dyn Error>> {
    let error = ByteRange::new(u64::MAX, u64::MAX)
        .expect_err("no total length can exceed the final u64 index");
    assert_eq!(error.code(), ResourceErrorCode::InvalidValue);
    assert!(ByteRange::new(u64::MAX - 1, u64::MAX).is_err());
    let final_representable = ByteRange::new(u64::MAX - 1, u64::MAX - 1)?;
    assert_eq!(final_representable.length(), 1);
    Ok(())
}

#[test]
fn resource_extension_requirements_are_bounded() -> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let maximum_required = (0..32)
        .map(|index| exact_extension(&format!("io.omnius.required/e{index}"), "v1"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let maximum_declaration = exact_declaration(
        "maximum@v1",
        "omnius://catalog/maximum",
        capability.clone(),
        maximum_required,
    )?;
    assert!(
        ResourceCatalog::new(
            CatalogRevision::new("extension-maximum-1".to_owned())?,
            CacheControl::private(30)?,
            vec![maximum_declaration],
            Vec::new(),
        )
        .is_ok()
    );
    let excessive_required = (0..33)
        .map(|index| exact_extension(&format!("io.omnius.required/e{index}"), "v1"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let excessive_declaration = exact_declaration(
        "excessive@v1",
        "omnius://catalog/excessive",
        capability,
        excessive_required,
    )?;
    let error = ResourceCatalog::new(
        CatalogRevision::new("extension-excessive-1".to_owned())?,
        CacheControl::private(30)?,
        vec![excessive_declaration],
        Vec::new(),
    )
    .expect_err("declaration extension requirements exceed fixed bound");
    assert_eq!(error.code(), ResourceErrorCode::InvalidDeclaration);
    Ok(())
}

#[tokio::test]
async fn denied_ranged_probe_does_not_reveal_range_policy_or_invoke_kernel()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let target = PublicResourceName::new("hidden@v1".to_owned())?;
    let uri = ResourceUri::parse("omnius://catalog/hidden".to_owned())?;
    let declaration = ExactResourceDeclaration::new(
        metadata(target.as_str(), BTreeSet::new())?,
        uri.clone(),
        capability,
        TenantMode::Global,
        TenantBinding::Global,
        ResourceLimits::new(1_024, None, CacheControl::private(30)?)?,
    )?;
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("range-oracle-1".to_owned())?,
        CacheControl::private(30)?,
        vec![declaration],
        Vec::new(),
    )?);
    let (projection, invocations) = projection(
        catalog,
        Arc::new(NamedAuthorizer {
            allowed: BTreeSet::new(),
        }),
        Vec::new(),
    )?;
    let request = read_request(
        target,
        uri,
        Some(ByteRange::new(0, 0)?),
        context(None, Decision::Allow)?,
    )?;

    let error = projection
        .read(request)
        .await
        .expect_err("denied target must conceal unsupported ranges");

    assert_eq!(error.code(), ResourceErrorCode::Rejected);
    assert!(
        invocations
            .lock()
            .expect("invocation recording lock")
            .is_empty()
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one read contract checks text, binary, range, provenance, cache, and hierarchy"
)]
#[tokio::test]
async fn reads_decode_text_binary_range_provenance_cache_and_future_metadata_through_kernel()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let target = PublicResourceName::new("items@v1".to_owned())?;
    let uri_text = ResourceUri::parse("omnius://catalog/items/text".to_owned())?;
    let uri_binary = ResourceUri::parse("omnius://catalog/items/binary".to_owned())?;
    let uri_range = ResourceUri::parse("omnius://catalog/items/range".to_owned())?;
    let outputs = vec![
        canonical_output(
            uri_text.as_str(),
            "text/plain; charset=utf-8",
            json!({"kind": "text", "text": "hello"}),
            b"hello",
            None,
            Some(json!({
                "parent_uri": "omnius://catalog/items/root",
                "child_uris": ["omnius://catalog/items/child"],
                "next_cursor": "cursor:2"
            })),
        ),
        canonical_output(
            uri_binary.as_str(),
            "application/octet-stream",
            json!({"kind": "binary", "base64": STANDARD.encode([0_u8, 1, 2, 3])}),
            &[0, 1, 2, 3],
            None,
            None,
        ),
        canonical_output(
            uri_range.as_str(),
            "text/plain",
            json!({"kind": "text", "text": "ell"}),
            b"ell",
            Some(json!({
                "start": 1_000_000,
                "end_inclusive": 1_000_002,
                "total_length": 10_000_000
            })),
            None,
        ),
    ];
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("catalog-18".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![template_declaration(
            target.as_str(),
            "omnius://catalog/items/{item_id}",
            capability,
            TenantMode::Global,
            TenantBinding::Global,
            BTreeSet::new(),
            1_024,
        )?],
    )?);
    let (projection, invocations) = projection(catalog, Arc::new(AllowAll), outputs)?;

    let text = projection
        .read(read_request(
            target.clone(),
            uri_text,
            None,
            context(None, Decision::Allow)?,
        )?)
        .await?;
    let binary = projection
        .read(read_request(
            target.clone(),
            uri_binary,
            None,
            context(None, Decision::Allow)?,
        )?)
        .await?;
    let range = projection
        .read(read_request(
            target,
            uri_range,
            Some(ByteRange::new(1_000_000, 1_000_002)?),
            context(None, Decision::Allow)?,
        )?)
        .await?;

    assert_eq!(text.content().as_text(), Some("hello"));
    assert_eq!(text.mime_type().as_str(), "text/plain; charset=utf-8");
    assert_eq!(
        text.provenance().capability().id().as_str(),
        "tests.resource"
    );
    assert_eq!(text.cache().control(), CacheControl::private(30)?);
    assert_eq!(
        text.hierarchy().map(|hierarchy| hierarchy.children().len()),
        Some(1)
    );
    assert_eq!(
        text.object_reference()
            .map(|reference| reference.store().as_str()),
        Some("objects.primary")
    );
    assert_eq!(binary.content().as_binary(), Some(&[0, 1, 2, 3][..]));
    assert_eq!(
        range
            .range()
            .map(omnius_mcp_resources::ResourceRangeResponse::total_length),
        Some(10_000_000)
    );
    let seen = invocations.lock().expect("invocation recording lock");
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|(exposure, _)| *exposure == Exposure::McpResource)
    );
    assert_eq!(
        seen[2].1["range"],
        json!({"start": 1_000_000, "end_inclusive": 1_000_002})
    );
    Ok(())
}

#[tokio::test]
async fn text_charset_must_be_absent_or_utf8() -> Result<(), Box<dyn Error>> {
    assert!(MimeType::new("text/plain")?.is_utf8_compatible());
    assert!(MimeType::new("text/plain; charset=UTF-8")?.is_utf8_compatible());
    assert!(MimeType::new("application/json; charset=utf8")?.is_utf8_compatible());
    assert!(!MimeType::new("text/plain; charset=iso-8859-1")?.is_utf8_compatible());

    let capability = capability_key()?;
    let target = PublicResourceName::new("items@v1".to_owned())?;
    let uri = ResourceUri::parse("omnius://catalog/items/latin1".to_owned())?;
    let output = canonical_output(
        uri.as_str(),
        "text/plain; charset=iso-8859-1",
        json!({"kind": "text", "text": "canonical utf8"}),
        b"canonical utf8",
        None,
        None,
    );
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("mime-1".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![template_declaration(
            target.as_str(),
            "omnius://catalog/items/{item_id}",
            capability,
            TenantMode::Global,
            TenantBinding::Global,
            BTreeSet::new(),
            1_024,
        )?],
    )?);
    let (projection, _) = projection(catalog, Arc::new(AllowAll), vec![output])?;

    let error = projection
        .read(read_request(
            target,
            uri,
            None,
            context(None, Decision::Allow)?,
        )?)
        .await
        .expect_err("non-UTF-8 charset must not describe canonical text");

    assert_eq!(error.code(), ResourceErrorCode::InvalidOutput);
    Ok(())
}

#[tokio::test]
async fn cache_policy_allows_downgrades_and_rejects_visibility_upgrades()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let target = PublicResourceName::new("public-cache@v1".to_owned())?;
    let uri = ResourceUri::parse("omnius://catalog/cache/one".to_owned())?;
    let private_output = canonical_output_with_cache(
        uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "private"}),
        b"private",
        None,
        None,
        "private",
        20,
    );
    let no_store_output = canonical_output_with_cache(
        uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "no-store"}),
        b"no-store",
        None,
        None,
        "no_store",
        0,
    );
    let declaration = ResourceTemplateDeclaration::new(
        metadata(target.as_str(), BTreeSet::new())?,
        ResourceUriTemplate::parse("omnius://catalog/cache/{item_id}".to_owned())?,
        capability.clone(),
        TenantMode::Global,
        TenantBinding::Global,
        ResourceLimits::new(1_024, None, CacheControl::public(30)?)?,
    )?;
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("cache-downgrade-1".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![declaration],
    )?);
    let (cache_projection, _) = projection(
        catalog,
        Arc::new(AllowAll),
        vec![private_output, no_store_output],
    )?;

    let private = cache_projection
        .read(read_request(
            target.clone(),
            uri.clone(),
            None,
            context(None, Decision::Allow)?,
        )?)
        .await?;
    let no_store = cache_projection
        .read(read_request(
            target,
            uri,
            None,
            context(None, Decision::Allow)?,
        )?)
        .await?;

    assert_eq!(private.cache().control().scope(), CacheScope::Private);
    assert_eq!(no_store.cache().control().scope(), CacheScope::NoStore);

    let private_target = PublicResourceName::new("private-cache@v1".to_owned())?;
    let private_uri = ResourceUri::parse("omnius://catalog/private/one".to_owned())?;
    let public_output = canonical_output_with_cache(
        private_uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "public"}),
        b"public",
        None,
        None,
        "public",
        10,
    );
    let private_declaration = ResourceTemplateDeclaration::new(
        metadata(private_target.as_str(), BTreeSet::new())?,
        ResourceUriTemplate::parse("omnius://catalog/private/{item_id}".to_owned())?,
        capability,
        TenantMode::Global,
        TenantBinding::Global,
        ResourceLimits::new(1_024, None, CacheControl::private(30)?)?,
    )?;
    let private_catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("cache-upgrade-1".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![private_declaration],
    )?);
    let (private_projection, _) =
        projection(private_catalog, Arc::new(AllowAll), vec![public_output])?;

    let error = private_projection
        .read(read_request(
            private_target,
            private_uri,
            None,
            context(None, Decision::Allow)?,
        )?)
        .await
        .expect_err("private declaration must reject public result");
    assert_eq!(error.code(), ResourceErrorCode::InvalidOutput);
    Ok(())
}

#[tokio::test]
async fn hierarchy_operation_preserves_future_domain_contract_through_kernel()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let target = PublicResourceName::new("items@v1".to_owned())?;
    let uri = ResourceUri::parse("omnius://catalog/items/root".to_owned())?;
    let output = canonical_output(
        uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "children"}),
        b"children",
        None,
        Some(json!({
            "parent_uri": null,
            "child_uris": ["omnius://catalog/items/child"],
            "next_cursor": "cursor:2"
        })),
    );
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("hierarchy-1".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![template_declaration(
            target.as_str(),
            "omnius://catalog/items/{item_id}",
            capability,
            TenantMode::Global,
            TenantBinding::Global,
            BTreeSet::new(),
            1_024,
        )?],
    )?);
    let (projection, invocations) = projection(catalog, Arc::new(AllowAll), vec![output])?;
    let request = ResourceRequest::new(
        baseline_request_context(context(None, Decision::Allow)?, TenantMode::Global)?,
        ConfirmationEvidence::NotProvided,
        None,
        target,
        uri,
        ResourceOperation::list_children(1, None)?,
        None,
    )?;

    let result = projection.execute(request).await?;

    assert_eq!(
        result
            .hierarchy()
            .map(|hierarchy| hierarchy.children().len()),
        Some(1)
    );
    let seen = invocations.lock().expect("invocation recording lock");
    assert_eq!(seen[0].0, Exposure::McpResource);
    assert_eq!(
        seen[0].1["operation"],
        json!({"kind": "list_children", "limit": 1, "cursor": null})
    );
    Ok(())
}

#[tokio::test]
async fn hierarchy_rejects_direct_parent_and_child_self_cycles() -> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let target = PublicResourceName::new("items@v1".to_owned())?;
    let uri = ResourceUri::parse("omnius://catalog/items/root".to_owned())?;
    let parent_cycle = canonical_output(
        uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "parent"}),
        b"parent",
        None,
        Some(json!({
            "parent_uri": uri.as_str(),
            "child_uris": [],
            "next_cursor": null
        })),
    );
    let child_cycle = canonical_output(
        uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "child"}),
        b"child",
        None,
        Some(json!({
            "parent_uri": null,
            "child_uris": [uri.as_str()],
            "next_cursor": null
        })),
    );
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("hierarchy-cycles-1".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![template_declaration(
            target.as_str(),
            "omnius://catalog/items/{item_id}",
            capability,
            TenantMode::Global,
            TenantBinding::Global,
            BTreeSet::new(),
            1_024,
        )?],
    )?);
    let (projection, _) = projection(catalog, Arc::new(AllowAll), vec![parent_cycle, child_cycle])?;

    for expected_cycle in ["parent", "child"] {
        let error = projection
            .read(read_request(
                target.clone(),
                uri.clone(),
                None,
                context(None, Decision::Allow)?,
            )?)
            .await
            .expect_err("direct hierarchy self-cycle must fail closed");
        assert_eq!(
            error.code(),
            ResourceErrorCode::InvalidOutput,
            "{expected_cycle}"
        );
    }
    Ok(())
}

#[test]
fn uri_parser_rejects_traversal_encoded_traversal_and_fetch_semantics() {
    for rejected in [
        "omnius://catalog/a/../b",
        "omnius://catalog/a/%2E%2E/b",
        "omnius://catalog/a/%252E%252E/b",
        "omnius://catalog/a/%2g/b",
        "omnius://catalog/a/%00/b",
        "omnius://catalog/a/%5C/b",
        "omnius://catalog/a/%2F/b",
        "omnius://user@catalog/items/a",
        "omnius://catalog/items/a#fragment",
        "omnius://catalog/items/a\\b",
        "http://catalog/items/a",
        "https://catalog/items/a",
        "file://catalog/items/a",
        "smb://catalog/items/a",
    ] {
        assert!(
            ResourceUri::parse(rejected.to_owned()).is_err(),
            "{rejected}"
        );
    }
    let sensitive = "https://credential@example.invalid/private";
    let error = ResourceUri::parse(sensitive.to_owned()).expect_err("fetch URI must fail");
    let rendered = format!("{error} {error:?}");
    assert_eq!(
        rendered,
        "MCP resource projection failed ResourceError([redacted])"
    );
    assert!(!rendered.contains(sensitive));
}

#[test]
fn catalog_rejects_ambiguous_templates_and_cross_registration_overlap() -> Result<(), Box<dyn Error>>
{
    let capability = capability_key()?;
    assert!(
        ResourceUriTemplate::parse("omnius://catalog/items/prefix-{item_id}".to_owned()).is_err()
    );
    assert!(ResourceUriTemplate::parse("omnius://catalog/items/{TenantId}".to_owned()).is_err());
    let first = template_declaration(
        "first@v1",
        "omnius://catalog/{kind}/fixed",
        capability.clone(),
        TenantMode::Global,
        TenantBinding::Global,
        BTreeSet::new(),
        100,
    )?;
    let second = template_declaration(
        "second@v1",
        "omnius://catalog/items/{item_id}",
        capability.clone(),
        TenantMode::Global,
        TenantBinding::Global,
        BTreeSet::new(),
        100,
    )?;
    let error = ResourceCatalog::new(
        CatalogRevision::new("ambiguous-1".to_owned())?,
        CacheControl::private(1)?,
        Vec::new(),
        vec![first, second],
    )
    .expect_err("overlapping templates must fail closed");
    assert_eq!(error.code(), ResourceErrorCode::InvalidDeclaration);

    let exact = exact_declaration(
        "exact@v1",
        "omnius://catalog/items/one",
        capability.clone(),
        BTreeSet::new(),
    )?;
    let template = template_declaration(
        "template@v1",
        "omnius://catalog/items/{item_id}",
        capability.clone(),
        TenantMode::Global,
        TenantBinding::Global,
        BTreeSet::new(),
        100,
    )?;
    assert!(
        ResourceCatalog::new(
            CatalogRevision::new("overlap-1".to_owned())?,
            CacheControl::private(1)?,
            vec![exact],
            vec![template],
        )
        .is_err()
    );
    let active = exact_declaration(
        "active@v1",
        "omnius://catalog/active",
        capability.clone(),
        BTreeSet::new(),
    )?;
    let deprecated_replacement = deprecated_exact_declaration(
        "newer@v1",
        "omnius://catalog/newer",
        "active@v1",
        capability.clone(),
    )?;
    let deprecated = deprecated_exact_declaration(
        "oldest@v1",
        "omnius://catalog/oldest",
        "newer@v1",
        capability,
    )?;
    assert!(
        ResourceCatalog::new(
            CatalogRevision::new("replacement-1".to_owned())?,
            CacheControl::private(1)?,
            vec![active, deprecated_replacement, deprecated],
            Vec::new(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn catalog_successor_accepts_classified_deprecation_and_eventual_removal()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let baseline = ResourceCatalog::new(
        CatalogRevision::new("successor-baseline".to_owned())?,
        CacheControl::private(30)?,
        vec![versioned_exact_declaration(
            "entry@v1",
            "omnius://catalog/entry-v1",
            "schema-1",
            ResourceCompatibility::Active,
            capability.clone(),
        )?],
        Vec::new(),
    )?;
    let window = ResourceCatalog::new(
        CatalogRevision::new("successor-window".to_owned())?,
        CacheControl::private(30)?,
        vec![
            versioned_exact_declaration(
                "entry@v1",
                "omnius://catalog/entry-v1",
                "schema-1",
                ResourceCompatibility::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-2".to_owned())?,
                    change: McpContractChange::SchemaAndSemantic,
                    replacement: Some(PublicResourceName::new("entry@v2".to_owned())?),
                },
                capability.clone(),
            )?,
            versioned_exact_declaration(
                "entry@v2",
                "omnius://catalog/entry-v2",
                "schema-2",
                ResourceCompatibility::Active,
                capability.clone(),
            )?,
        ],
        Vec::new(),
    )?;

    baseline.validate_successor(&window)?;
    let compatibility = window
        .exact_resources()
        .next()
        .expect("deprecated v1 declaration")
        .metadata()
        .compatibility();
    assert_eq!(
        compatibility
            .since_schema_revision()
            .map(SchemaRevision::as_str),
        Some("schema-2")
    );
    assert_eq!(
        compatibility.change(),
        Some(McpContractChange::SchemaAndSemantic)
    );
    assert_eq!(
        serde_json::to_value(compatibility)?,
        json!({
            "status": "deprecated",
            "since_schema_revision": "schema-2",
            "change": "schema_and_semantic",
            "replacement": "entry@v2"
        })
    );

    let after_window = ResourceCatalog::new(
        CatalogRevision::new("successor-after-window".to_owned())?,
        CacheControl::private(30)?,
        vec![versioned_exact_declaration(
            "entry@v2",
            "omnius://catalog/entry-v2",
            "schema-2",
            ResourceCompatibility::Active,
            capability,
        )?],
        Vec::new(),
    )?;
    window.validate_successor(&after_window)?;
    Ok(())
}

#[test]
fn catalog_successor_rejects_active_removal_and_deprecated_reactivation()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let active = ResourceCatalog::new(
        CatalogRevision::new("active-removal-baseline".to_owned())?,
        CacheControl::private(30)?,
        vec![versioned_exact_declaration(
            "entry@v1",
            "omnius://catalog/entry-v1",
            "schema-1",
            ResourceCompatibility::Active,
            capability.clone(),
        )?],
        Vec::new(),
    )?;
    let empty = ResourceCatalog::new(
        CatalogRevision::new("active-removal-successor".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        Vec::new(),
    )?;
    let removal_error = active
        .validate_successor(&empty)
        .expect_err("active public names cannot be removed");
    assert_eq!(removal_error.code(), ResourceErrorCode::InvalidDeclaration);

    let deprecated = ResourceCatalog::new(
        CatalogRevision::new("reactivation-baseline".to_owned())?,
        CacheControl::private(30)?,
        vec![
            versioned_exact_declaration(
                "entry@v1",
                "omnius://catalog/entry-v1",
                "schema-1",
                ResourceCompatibility::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-2".to_owned())?,
                    change: McpContractChange::Schema,
                    replacement: Some(PublicResourceName::new("entry@v2".to_owned())?),
                },
                capability.clone(),
            )?,
            versioned_exact_declaration(
                "entry@v2",
                "omnius://catalog/entry-v2",
                "schema-2",
                ResourceCompatibility::Active,
                capability.clone(),
            )?,
        ],
        Vec::new(),
    )?;
    let reactivated = ResourceCatalog::new(
        CatalogRevision::new("reactivation-successor".to_owned())?,
        CacheControl::private(30)?,
        vec![
            versioned_exact_declaration(
                "entry@v1",
                "omnius://catalog/entry-v1",
                "schema-1",
                ResourceCompatibility::Active,
                capability.clone(),
            )?,
            versioned_exact_declaration(
                "entry@v2",
                "omnius://catalog/entry-v2",
                "schema-2",
                ResourceCompatibility::Active,
                capability,
            )?,
        ],
        Vec::new(),
    )?;
    assert_eq!(
        deprecated
            .validate_successor(&reactivated)
            .expect_err("deprecated public names cannot be reactivated")
            .code(),
        ResourceErrorCode::InvalidDeclaration
    );
    Ok(())
}

#[test]
fn catalog_successor_rejects_changed_deprecation_window() -> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let baseline = ResourceCatalog::new(
        CatalogRevision::new("window-baseline".to_owned())?,
        CacheControl::private(30)?,
        vec![
            versioned_exact_declaration(
                "entry@v1",
                "omnius://catalog/entry-v1",
                "schema-1",
                ResourceCompatibility::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-2".to_owned())?,
                    change: McpContractChange::Schema,
                    replacement: Some(PublicResourceName::new("entry@v2".to_owned())?),
                },
                capability.clone(),
            )?,
            versioned_exact_declaration(
                "entry@v2",
                "omnius://catalog/entry-v2",
                "schema-2",
                ResourceCompatibility::Active,
                capability.clone(),
            )?,
        ],
        Vec::new(),
    )?;
    let changed_window = ResourceCatalog::new(
        CatalogRevision::new("window-successor".to_owned())?,
        CacheControl::private(30)?,
        vec![
            versioned_exact_declaration(
                "entry@v1",
                "omnius://catalog/entry-v1",
                "schema-1",
                ResourceCompatibility::Deprecated {
                    since_schema_revision: SchemaRevision::new("schema-2".to_owned())?,
                    change: McpContractChange::Semantic,
                    replacement: Some(PublicResourceName::new("entry@v2".to_owned())?),
                },
                capability.clone(),
            )?,
            versioned_exact_declaration(
                "entry@v2",
                "omnius://catalog/entry-v2",
                "schema-2",
                ResourceCompatibility::Active,
                capability,
            )?,
        ],
        Vec::new(),
    )?;

    assert_eq!(
        baseline
            .validate_successor(&changed_window)
            .expect_err("a documented deprecation window is immutable")
            .code(),
        ResourceErrorCode::InvalidDeclaration
    );
    Ok(())
}

#[test]
fn catalog_successor_rejects_same_name_schema_capability_and_kind_mutation()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let baseline = ResourceCatalog::new(
        CatalogRevision::new("contract-baseline".to_owned())?,
        CacheControl::private(30)?,
        vec![versioned_exact_declaration(
            "entry@v1",
            "omnius://catalog/entry-v1",
            "schema-1",
            ResourceCompatibility::Active,
            capability.clone(),
        )?],
        Vec::new(),
    )?;
    let schema_mutation = ResourceCatalog::new(
        CatalogRevision::new("contract-schema-mutation".to_owned())?,
        CacheControl::private(30)?,
        vec![versioned_exact_declaration(
            "entry@v1",
            "omnius://catalog/entry-v1",
            "schema-2",
            ResourceCompatibility::Active,
            capability.clone(),
        )?],
        Vec::new(),
    )?;
    assert!(
        baseline.validate_successor(&schema_mutation).is_err(),
        "schema mutation under a shared name must fail"
    );

    let changed_capability =
        CapabilityKey::new("tests.resource.changed".parse()?, "1.0.0".parse()?);
    let capability_mutation = ResourceCatalog::new(
        CatalogRevision::new("contract-capability-mutation".to_owned())?,
        CacheControl::private(30)?,
        vec![versioned_exact_declaration(
            "entry@v1",
            "omnius://catalog/entry-v1",
            "schema-1",
            ResourceCompatibility::Active,
            changed_capability,
        )?],
        Vec::new(),
    )?;
    assert!(
        baseline.validate_successor(&capability_mutation).is_err(),
        "semantic capability mutation under a shared name must fail"
    );

    let kind_mutation = ResourceCatalog::new(
        CatalogRevision::new("contract-kind-mutation".to_owned())?,
        CacheControl::private(30)?,
        Vec::new(),
        vec![template_declaration(
            "entry@v1",
            "omnius://catalog/entry-v1/{item_id}",
            capability,
            TenantMode::Global,
            TenantBinding::Global,
            BTreeSet::new(),
            1_024,
        )?],
    )?;
    assert_eq!(
        baseline
            .validate_successor(&kind_mutation)
            .expect_err("exact and template kinds are immutable")
            .code(),
        ResourceErrorCode::InvalidDeclaration
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one isolation contract exercises cross-target and cross-tenant request contexts"
)]
#[tokio::test]
async fn cross_target_and_cross_tenant_uris_are_rejected_before_kernel()
-> Result<(), Box<dyn Error>> {
    let capability = capability_key()?;
    let alpha = exact_declaration(
        "alpha@v1",
        "omnius://catalog/alpha",
        capability.clone(),
        BTreeSet::new(),
    )?;
    let beta = exact_declaration(
        "beta@v1",
        "omnius://catalog/beta",
        capability.clone(),
        BTreeSet::new(),
    )?;
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("targets-1".to_owned())?,
        CacheControl::private(1)?,
        vec![alpha, beta],
        Vec::new(),
    )?);
    let (global_projection, invocations) = projection(catalog, Arc::new(AllowAll), Vec::new())?;
    let request = read_request(
        PublicResourceName::new("alpha@v1".to_owned())?,
        ResourceUri::parse("omnius://catalog/beta".to_owned())?,
        None,
        context(None, Decision::Allow)?,
    )?;
    assert_eq!(
        global_projection
            .read(request)
            .await
            .expect_err("cross target")
            .code(),
        ResourceErrorCode::Rejected
    );
    assert!(
        invocations
            .lock()
            .expect("invocation recording lock")
            .is_empty()
    );

    let tenant = TenantId::new();
    let other_tenant = TenantId::new();
    let tenant_catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("tenants-1".to_owned())?,
        CacheControl::private(1)?,
        Vec::new(),
        vec![template_declaration(
            "tenant-items@v1",
            "omnius://catalog/tenants/{tenant_id}/items/{item_id}",
            capability,
            TenantMode::Tenant,
            TenantBinding::PathVariable(TemplateVariableName::new("tenant_id".to_owned())?),
            BTreeSet::new(),
            100,
        )?],
    )?);
    let (tenant_projection, tenant_invocations) =
        projection(tenant_catalog, Arc::new(AllowAll), Vec::new())?;
    let uri = ResourceUri::parse(format!("omnius://catalog/tenants/{other_tenant}/items/one"))?;
    let request = ResourceRequest::new(
        baseline_request_context(context(Some(tenant), Decision::Allow)?, TenantMode::Tenant)?,
        ConfirmationEvidence::NotProvided,
        None,
        PublicResourceName::new("tenant-items@v1".to_owned())?,
        uri,
        ResourceOperation::Read,
        None,
    )?;
    assert_eq!(
        tenant_projection
            .read(request)
            .await
            .expect_err("cross tenant URI")
            .code(),
        ResourceErrorCode::Rejected
    );
    let wrong_mode = ResourceRequest::new(
        baseline_request_context(
            context(Some(tenant), Decision::Allow)?,
            TenantMode::Principal,
        )?,
        ConfirmationEvidence::NotProvided,
        None,
        PublicResourceName::new("tenant-items@v1".to_owned())?,
        ResourceUri::parse(format!("omnius://catalog/tenants/{tenant}/items/two"))?,
        ResourceOperation::Read,
        None,
    )?;
    assert_eq!(
        tenant_projection
            .read(wrong_mode)
            .await
            .expect_err("wrong selected tenant mode")
            .code(),
        ResourceErrorCode::Rejected
    );
    assert!(
        tenant_invocations
            .lock()
            .expect("invocation recording lock")
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn canonical_registry_denial_and_oversized_output_fail_closed() -> Result<(), Box<dyn Error>>
{
    let capability = capability_key()?;
    let tenant = TenantId::new();
    let uri = ResourceUri::parse(format!("omnius://catalog/tenants/{tenant}/items/one"))?;
    let catalog = Arc::new(ResourceCatalog::new(
        CatalogRevision::new("bounds-1".to_owned())?,
        CacheControl::private(1)?,
        Vec::new(),
        vec![template_declaration(
            "tenant-items@v1",
            "omnius://catalog/tenants/{tenant_id}/items/{item_id}",
            capability,
            TenantMode::Tenant,
            TenantBinding::PathVariable(TemplateVariableName::new("tenant_id".to_owned())?),
            BTreeSet::new(),
            5,
        )?],
    )?);
    let oversized = canonical_output(
        uri.as_str(),
        "text/plain",
        json!({"kind": "text", "text": "123456"}),
        b"123456",
        None,
        None,
    );
    let (projection, invocations) = projection(catalog, Arc::new(AllowAll), vec![oversized])?;
    let denied = ResourceRequest::new(
        baseline_request_context(
            context(Some(tenant), Decision::Deny(DenyReason::TenantMismatch))?,
            TenantMode::Tenant,
        )?,
        ConfirmationEvidence::NotProvided,
        None,
        PublicResourceName::new("tenant-items@v1".to_owned())?,
        uri.clone(),
        ResourceOperation::Read,
        None,
    )?;
    assert_eq!(
        projection
            .read(denied)
            .await
            .expect_err("registry denial")
            .code(),
        ResourceErrorCode::Rejected
    );
    assert!(
        invocations
            .lock()
            .expect("invocation recording lock")
            .is_empty()
    );

    let oversized = ResourceRequest::new(
        baseline_request_context(context(Some(tenant), Decision::Allow)?, TenantMode::Tenant)?,
        ConfirmationEvidence::NotProvided,
        None,
        PublicResourceName::new("tenant-items@v1".to_owned())?,
        uri,
        ResourceOperation::Read,
        None,
    )?;
    assert_eq!(
        projection
            .read(oversized)
            .await
            .expect_err("oversized output")
            .code(),
        ResourceErrorCode::InvalidOutput
    );
    assert_eq!(
        invocations.lock().expect("invocation recording lock").len(),
        1
    );
    Ok(())
}

fn projection(
    catalog: Arc<ResourceCatalog>,
    authorizer: Arc<dyn ResourceAuthorizer>,
    outputs: Vec<Value>,
) -> Result<(ResourceProjection, RecordedInvocations), Box<dyn Error>> {
    projection_with_availability(catalog, authorizer, outputs, RuntimeAvailability::Available)
}

fn projection_with_availability(
    catalog: Arc<ResourceCatalog>,
    authorizer: Arc<dyn ResourceAuthorizer>,
    outputs: Vec<Value>,
    availability: RuntimeAvailability,
) -> Result<(ResourceProjection, RecordedInvocations), Box<dyn Error>> {
    let invocations = Arc::new(Mutex::new(Vec::new()));
    let handler = RecordingHandler {
        outputs: Arc::new(Mutex::new(outputs.into())),
        invocations: Arc::clone(&invocations),
    };
    let mut builder = CapabilityRegistryBuilder::new();
    builder.register(capability_document()?, availability, handler)?;
    let kernel = Arc::new(McpKernel::new(Arc::new(builder.build())));
    Ok((
        ResourceProjection::new(kernel, catalog, authorizer)?,
        invocations,
    ))
}

fn exact_declaration(
    name: &str,
    uri: &str,
    capability: CapabilityKey,
    extensions: BTreeSet<McpExtension>,
) -> Result<ExactResourceDeclaration, Box<dyn Error>> {
    Ok(ExactResourceDeclaration::new(
        metadata(name, extensions)?,
        ResourceUri::parse(uri.to_owned())?,
        capability,
        TenantMode::Global,
        TenantBinding::Global,
        ResourceLimits::new(1_024, Some(128), CacheControl::private(30)?)?,
    )?)
}

fn versioned_exact_declaration(
    name: &str,
    uri: &str,
    schema_revision: &str,
    compatibility: ResourceCompatibility,
    capability: CapabilityKey,
) -> Result<ExactResourceDeclaration, Box<dyn Error>> {
    Ok(ExactResourceDeclaration::new(
        ResourceMetadata::new(
            PublicResourceName::new(name.to_owned())?,
            ResourceTitle::new(format!("Resource {name}"))?,
            None,
            SchemaRevision::new(schema_revision.to_owned())?,
            compatibility,
            None,
            BTreeSet::new(),
        ),
        ResourceUri::parse(uri.to_owned())?,
        capability,
        TenantMode::Global,
        TenantBinding::Global,
        ResourceLimits::new(1_024, Some(128), CacheControl::private(30)?)?,
    )?)
}

fn deprecated_exact_declaration(
    name: &str,
    uri: &str,
    replacement: &str,
    capability: CapabilityKey,
) -> Result<ExactResourceDeclaration, Box<dyn Error>> {
    Ok(ExactResourceDeclaration::new(
        ResourceMetadata::new(
            PublicResourceName::new(name.to_owned())?,
            ResourceTitle::new(format!("Resource {name}"))?,
            None,
            SchemaRevision::new("schema-2".to_owned())?,
            ResourceCompatibility::Deprecated {
                since_schema_revision: SchemaRevision::new("schema-2".to_owned())?,
                change: McpContractChange::Semantic,
                replacement: Some(PublicResourceName::new(replacement.to_owned())?),
            },
            None,
            BTreeSet::new(),
        ),
        ResourceUri::parse(uri.to_owned())?,
        capability,
        TenantMode::Global,
        TenantBinding::Global,
        ResourceLimits::new(1_024, Some(128), CacheControl::private(30)?)?,
    )?)
}

fn template_declaration(
    name: &str,
    uri_template: &str,
    capability: CapabilityKey,
    tenant_mode: TenantMode,
    tenant_binding: TenantBinding,
    extensions: BTreeSet<McpExtension>,
    max_content_bytes: u64,
) -> Result<ResourceTemplateDeclaration, Box<dyn Error>> {
    Ok(ResourceTemplateDeclaration::new(
        metadata(name, extensions)?,
        ResourceUriTemplate::parse(uri_template.to_owned())?,
        capability,
        tenant_mode,
        tenant_binding,
        ResourceLimits::new(
            max_content_bytes,
            Some(max_content_bytes.min(128)),
            CacheControl::private(30)?,
        )?,
    )?)
}

fn metadata(
    name: &str,
    extensions: BTreeSet<McpExtension>,
) -> Result<ResourceMetadata, Box<dyn Error>> {
    Ok(ResourceMetadata::new(
        PublicResourceName::new(name.to_owned())?,
        ResourceTitle::new(format!("Resource {name}"))?,
        None,
        SchemaRevision::new("schema-1".to_owned())?,
        ResourceCompatibility::Active,
        None,
        extensions,
    ))
}

fn read_request(
    target: PublicResourceName,
    uri: ResourceUri,
    range: Option<ByteRange>,
    context: InvocationContext,
) -> Result<ResourceRequest, Box<dyn Error>> {
    read_request_with_context(
        target,
        uri,
        range,
        baseline_request_context(context, TenantMode::Global)?,
    )
}

fn read_request_with_context(
    target: PublicResourceName,
    uri: ResourceUri,
    range: Option<ByteRange>,
    request_context: McpRequestContext,
) -> Result<ResourceRequest, Box<dyn Error>> {
    Ok(ResourceRequest::new(
        request_context,
        ConfirmationEvidence::NotProvided,
        None,
        target,
        uri,
        ResourceOperation::Read,
        range,
    )?)
}

fn capability_key() -> Result<CapabilityKey, Box<dyn Error>> {
    Ok(CapabilityKey::new(
        "tests.resource".parse()?,
        "1.0.0".parse()?,
    ))
}

fn capability_document() -> Result<CapabilityDocument, serde_json::Error> {
    serde_json::from_value(json!({
        "id": "tests.resource",
        "version": "1.0.0",
        "title": "Resource projection fixture",
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
        "tenant_modes": ["global", "tenant"],
        "exposures": ["mcp-resource"]
    }))
}

fn exact_extension(id: &str, revision: &str) -> Result<McpExtension, Box<dyn Error>> {
    Ok(McpExtension::new(
        McpExtensionId::new(id)?,
        McpExtensionRevision::new(revision)?,
    ))
}

fn baseline_request_context(
    invocation: InvocationContext,
    tenant_mode: TenantMode,
) -> Result<McpRequestContext, Box<dyn Error>> {
    request_context(invocation, tenant_mode, Vec::new(), Vec::new())
}

fn request_context(
    invocation: InvocationContext,
    tenant_mode: TenantMode,
    requested_extensions: Vec<McpExtension>,
    supported_extensions: Vec<McpExtension>,
) -> Result<McpRequestContext, Box<dyn Error>> {
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("mcp-resources-tests", "1")?,
        Vec::new(),
        requested_extensions,
        None,
    )?;
    let extension_catalog = McpExtensionCatalog::new(supported_extensions)?;
    let canonical = McpCanonicalContext::new(invocation, tenant_mode)?;
    Ok(McpRequestContext::new(
        metadata,
        &extension_catalog,
        canonical,
    ))
}

fn context(
    tenant: Option<TenantId>,
    decision: Decision,
) -> Result<InvocationContext, Box<dyn Error>> {
    context_with_tenants(tenant, tenant, decision)
}

fn context_with_tenants(
    principal_tenant: Option<TenantId>,
    context_tenant: Option<TenantId>,
    decision: Decision,
) -> Result<InvocationContext, Box<dyn Error>> {
    let principal = Principal::new(
        SubjectId::new(),
        PrincipalKind::ServiceAccount,
        principal_tenant,
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
        context_tenant,
        decision,
        "policy.mcp-resources".parse()?,
        BudgetBounds::new(64 * 1_024, 64 * 1_024, 1_000)?,
        OffsetDateTime::now_utc() + time::Duration::seconds(30),
        CancellationToken::new(),
    )?)
}

fn canonical_output(
    uri: &str,
    mime_type: &str,
    content: Value,
    decoded_content: &[u8],
    range: Option<Value>,
    hierarchy: Option<Value>,
) -> Value {
    canonical_output_with_cache(
        uri,
        mime_type,
        content,
        decoded_content,
        range,
        hierarchy,
        "private",
        30,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test fixture names every canonical cache field"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "the JSON fixture owns content and optional sections for readable call sites"
)]
fn canonical_output_with_cache(
    uri: &str,
    mime_type: &str,
    content: Value,
    decoded_content: &[u8],
    range: Option<Value>,
    hierarchy: Option<Value>,
    cache_scope: &str,
    max_age_seconds: u32,
) -> Value {
    let checksum = digest(decoded_content);
    json!({
        "uri": uri,
        "mime_type": mime_type,
        "content": content,
        "provenance": {
            "capability_id": "tests.resource",
            "capability_version": "1.0.0",
            "source_revision": "source:17"
        },
        "cache": {
            "scope": cache_scope,
            "max_age_seconds": max_age_seconds,
            "etag": checksum
        },
        "range": range,
        "hierarchy": hierarchy,
        "checksum": checksum,
        "object_reference": {
            "store": "objects.primary",
            "object_id": "object:17",
            "version": "version:3"
        }
    })
}

fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::from("sha256:");
    for byte in digest {
        value.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        value.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    value
}
