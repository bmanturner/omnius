//! Trusted, bounded metadata projection for an explicitly experimental server-card preview.
//!
//! This crate defines neither an MCP capability nor a proprietary RPC. A public report can be
//! created only from an immutable registry-minted snapshot filtered for one canonical request,
//! principal, tenant, exact extension revision, and fresh authorization context. Retained raw
//! metadata and ownership provenance have no serialization path into the report adapter.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod metadata;
mod preview;
mod report;

pub use metadata::{
    AuthorizedMetadataSnapshot, HARD_MAX_METADATA_BYTES, HARD_MAX_METADATA_DEPTH,
    HARD_MAX_METADATA_KEYS, HARD_MAX_METADATA_STRING_BYTES, HARD_MAX_SNAPSHOT_TTL_SECONDS,
    MetaDocument, MetadataAccessPolicy, MetadataError, MetadataInertReason, MetadataKey,
    MetadataKeyRegistry, MetadataLifecycle, MetadataLimits, MetadataOwner, MetadataRegistration,
    MetadataResolution, MetadataSnapshotTtl, MetadataTelemetryReport, MetadataVersionRange,
    RegisteredMetadata, VersionedMetadataValue,
};
pub use preview::{
    ExperimentalPreviewConfig, PreviewReasonCode, SERVER_METADATA_PREVIEW_ID,
    SERVER_METADATA_PREVIEW_REVISION,
};
pub use report::{
    HARD_MAX_PREVIEW_REPORT_BYTES, MetadataReportAdapter, PreviewMetadataReport,
    PreviewReportError, SERVER_METADATA_PREVIEW_ROUTE,
};

#[cfg(test)]
mod test_support {
    use omnius_agent_capability_registry::{
        BudgetBounds, InvocationContext, TenantMode, TraceContext,
    };
    use omnius_auth_core::{
        AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
    };
    use omnius_authz_basic::Decision;
    use omnius_core::RequestId;
    use omnius_mcp_server_core::{
        MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
        McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
        McpRequestMetadata,
    };
    use time::OffsetDateTime;
    use tokio_util::sync::CancellationToken;

    use crate::SERVER_METADATA_PREVIEW_ID;

    pub(crate) struct RequestContextOptions {
        pub(crate) requested_revision: Option<&'static str>,
        pub(crate) supported_revision: Option<&'static str>,
        pub(crate) subject_id: Option<SubjectId>,
        pub(crate) tenant_id: Option<TenantId>,
        pub(crate) decision: Decision,
    }

    impl Default for RequestContextOptions {
        fn default() -> Self {
            Self {
                requested_revision: None,
                supported_revision: None,
                subject_id: None,
                tenant_id: None,
                decision: Decision::Allow,
            }
        }
    }

    pub(crate) fn request_context(
        options: &RequestContextOptions,
    ) -> Result<McpRequestContext, Box<dyn std::error::Error>> {
        let requested_extensions = options
            .requested_revision
            .map(extension)
            .transpose()?
            .into_iter();
        let supported_extensions = options
            .supported_revision
            .map(extension)
            .transpose()?
            .into_iter();
        let metadata = McpRequestMetadata::new(
            MCP_PROTOCOL_REVISION,
            McpClientIdentity::new("server-card-preview-tests", "1")?,
            std::iter::empty(),
            requested_extensions,
            None,
        )?;
        let catalog = McpExtensionCatalog::new(supported_extensions)?;
        let principal = Principal::new(
            options.subject_id.unwrap_or_default(),
            PrincipalKind::ServiceAccount,
            options.tenant_id,
            AuthMethod::ApiKey,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal1,
            vec![Scope::new("metadata:read")?],
        )?;
        let invocation = InvocationContext::new(
            RequestId::new(),
            TraceContext::new(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
                None,
            ),
            principal,
            options.tenant_id,
            options.decision,
            "policy.mcp-card-preview".parse()?,
            BudgetBounds::new(65_536, 65_536, 1_000)?,
            OffsetDateTime::now_utc() + time::Duration::minutes(2),
            CancellationToken::new(),
        )?;
        let tenant_mode = if options.tenant_id.is_some() {
            TenantMode::Tenant
        } else {
            TenantMode::Global
        };
        let canonical = McpCanonicalContext::new(invocation, tenant_mode)?;
        Ok(McpRequestContext::new(metadata, &catalog, canonical))
    }

    fn extension(revision: &str) -> Result<McpExtension, Box<dyn std::error::Error>> {
        Ok(McpExtension::new(
            McpExtensionId::new(SERVER_METADATA_PREVIEW_ID)?,
            McpExtensionRevision::new(revision)?,
        ))
    }
}
