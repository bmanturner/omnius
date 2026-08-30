use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use omnius_mcp_server_core::McpRequestContext;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::{
    AuthorizedMetadataSnapshot, ExperimentalPreviewConfig, HARD_MAX_METADATA_BYTES,
    PreviewReasonCode, SERVER_METADATA_PREVIEW_ID, metadata::encoded_fingerprint,
};

/// The sole catalog-owned HTTP route for the experimental metadata preview.
pub const SERVER_METADATA_PREVIEW_ROUTE: &str = "/.well-known/mcp-preview.json";
/// Maximum encoded report size, including the fixed experimental and evidence envelope.
pub const HARD_MAX_PREVIEW_REPORT_BYTES: usize = HARD_MAX_METADATA_BYTES + 2_048;

/// Transport-neutral adapter for the catalog-owned experimental metadata report route.
#[derive(Clone, Copy, Debug, Default)]
pub struct MetadataReportAdapter;

impl MetadataReportAdapter {
    /// Returns the sole route the HTTP composition adapter may register.
    #[must_use]
    pub const fn route() -> &'static str {
        SERVER_METADATA_PREVIEW_ROUTE
    }

    /// Renders only a fresh immutable authorized snapshot for an exactly negotiated request.
    ///
    /// Explicit experimental server configuration and the exact request-scoped extension revision
    /// are both required. The adapter cannot accept a raw [`crate::MetaDocument`], and therefore
    /// cannot publish unknown, parsed, forwarded, wrong-owner, cross-tenant, unauthorized,
    /// deprecated-disallowed, removed, or version-mismatched keys.
    ///
    /// The output is deliberately marked unstable and experimental. It is not an MCP capability,
    /// RPC result, conformance document, stable schema, or replacement for standard discovery.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for inactive configuration/negotiation, stale or wrong-context
    /// snapshot evidence, clock failure, serialization failure, or output-size violation.
    pub fn render(
        snapshot: &AuthorizedMetadataSnapshot,
        config: ExperimentalPreviewConfig,
        request: &McpRequestContext,
    ) -> Result<PreviewMetadataReport, PreviewReportError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PreviewReportError::SnapshotUnavailable)?
            .as_secs();
        Self::render_at(snapshot, config, request, now_unix)
    }

    pub(crate) fn render_at(
        snapshot: &AuthorizedMetadataSnapshot,
        config: ExperimentalPreviewConfig,
        request: &McpRequestContext,
        now_unix: u64,
    ) -> Result<PreviewMetadataReport, PreviewReportError> {
        let revision = config
            .negotiated_revision(request)
            .map_err(PreviewReportError::Inactive)?;
        snapshot
            .validate_for(request, now_unix)
            .map_err(|_| PreviewReportError::SnapshotUnavailable)?;

        let authorized_set_fingerprint = snapshot.authorized_set_fingerprint();
        let evidence_fingerprint = snapshot.evidence_fingerprint();
        let envelope = ReportEnvelope {
            preview: PreviewEnvelope {
                identifier: SERVER_METADATA_PREVIEW_ID,
                revision,
                stability: "unstable",
                status: "experimental",
            },
            snapshot: SnapshotEnvelope {
                authenticity: "server-derived-authorized-registry-snapshot",
                authorized_set_fingerprint: encoded_fingerprint(&authorized_set_fingerprint),
                evidence_fingerprint: encoded_fingerprint(&evidence_fingerprint),
                captured_at_unix: snapshot.captured_at_unix(),
                valid_until_unix: snapshot.valid_until_unix(),
            },
            metadata: snapshot.active(),
        };
        let body = serde_json::to_vec(&envelope).map_err(|_| PreviewReportError::Serialization)?;
        if body.len() > HARD_MAX_PREVIEW_REPORT_BYTES {
            return Err(PreviewReportError::OutputTooLarge);
        }
        Ok(PreviewMetadataReport {
            body,
            preview_revision: revision,
        })
    }
}

#[derive(Serialize)]
struct ReportEnvelope<'a> {
    preview: PreviewEnvelope<'a>,
    snapshot: SnapshotEnvelope,
    metadata: &'a std::collections::BTreeMap<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewEnvelope<'a> {
    identifier: &'static str,
    revision: &'a str,
    stability: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotEnvelope {
    authenticity: &'static str,
    authorized_set_fingerprint: String,
    evidence_fingerprint: String,
    captured_at_unix: u64,
    valid_until_unix: u64,
}

/// Experimental JSON report with mandatory private, non-cacheable response policy.
#[derive(Clone, Eq, PartialEq)]
pub struct PreviewMetadataReport {
    body: Vec<u8>,
    preview_revision: &'static str,
}

impl fmt::Debug for PreviewMetadataReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreviewMetadataReport")
            .field("body", &"[redacted]")
            .field("preview_revision", &self.preview_revision)
            .finish()
    }
}

impl PreviewMetadataReport {
    /// Returns `application/json`; no stable schema profile is claimed.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        "application/json"
    }

    /// Returns the mandatory cache policy for principal- and tenant-bound evidence.
    #[must_use]
    pub const fn cache_control(&self) -> &'static str {
        "private, no-store"
    }

    /// Returns an explicit experimental marker for the HTTP composition adapter.
    #[must_use]
    pub const fn experimental_header(&self) -> (&'static str, &'static str) {
        ("x-omnius-experimental", "server-metadata-preview")
    }

    /// Returns the exact request-negotiated experimental revision.
    #[must_use]
    pub const fn preview_revision(&self) -> &'static str {
        self.preview_revision
    }

    /// Returns the deterministic, already bounded JSON body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Fail-closed, value-free metadata report rendering failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreviewReportError {
    /// Experimental server configuration or exact request negotiation was inactive.
    #[error("metadata preview inactive")]
    Inactive(PreviewReasonCode),
    /// Snapshot evidence was stale, unauthorized, or bound to another canonical context.
    #[error("metadata preview snapshot unavailable")]
    SnapshotUnavailable,
    /// The filtered experimental report could not be serialized.
    #[error("metadata preview serialization failed")]
    Serialization,
    /// The filtered experimental report exceeded its fixed output ceiling.
    #[error("metadata preview output exceeds its fixed ceiling")]
    OutputTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MetaDocument, MetadataAccessPolicy, MetadataKey, MetadataKeyRegistry, MetadataLifecycle,
        MetadataLimits, MetadataOwner, MetadataRegistration, MetadataSnapshotTtl,
        MetadataVersionRange, SERVER_METADATA_PREVIEW_REVISION, VersionedMetadataValue,
        test_support::{RequestContextOptions, request_context},
    };

    fn exact_context() -> Result<McpRequestContext, Box<dyn std::error::Error>> {
        request_context(&RequestContextOptions {
            requested_revision: Some(SERVER_METADATA_PREVIEW_REVISION),
            supported_revision: Some(SERVER_METADATA_PREVIEW_REVISION),
            ..RequestContextOptions::default()
        })
    }

    fn key(value: &str) -> Result<MetadataKey, crate::MetadataError> {
        MetadataKey::parse(value)
    }

    fn owner() -> Result<MetadataOwner, crate::MetadataError> {
        MetadataOwner::parse("example-module")
    }

    fn registry(keys: &[&str]) -> Result<MetadataKeyRegistry, crate::MetadataError> {
        let owner = owner()?;
        let mut registrations = Vec::with_capacity(keys.len());
        for value in keys {
            registrations.push(MetadataRegistration::new(
                key(value)?,
                owner.clone(),
                MetadataVersionRange::try_new(1, 1)?,
                MetadataLifecycle::Stable,
            ));
        }
        MetadataKeyRegistry::try_new(registrations)
    }

    fn policy(keys: &[&str]) -> Result<MetadataAccessPolicy, crate::MetadataError> {
        MetadataAccessPolicy::try_new(false, false, keys.iter().map(|key| ((*key).to_owned(), 1)))
    }

    #[test]
    fn raw_parsed_and_unknown_metadata_cannot_enter_the_public_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = exact_context()?;
        let registry = registry(&["com.example/known"])?;
        let document = MetaDocument::parse_json(
            br#"{"com.example/known":{"version":1,"value":"raw-secret"},"future.example/key":"unknown-secret"}"#,
            MetadataLimits::default(),
        )?;
        let snapshot = registry.authorize_snapshot(
            &document,
            &policy(&["com.example/known"])?,
            &context,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        assert_eq!(snapshot.active_key_count(), 0);

        let report = MetadataReportAdapter::render(
            &snapshot,
            ExperimentalPreviewConfig::enabled(),
            &context,
        )?;
        let body = std::str::from_utf8(report.body())?;
        assert!(!body.contains("raw-secret"));
        assert!(!body.contains("unknown-secret"));
        assert!(!body.contains("future.example/key"));
        Ok(())
    }

    #[test]
    fn disabled_preview_and_exact_revision_mismatch_emit_no_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = exact_context()?;
        let registry = registry(&[])?;
        let snapshot = registry.authorize_snapshot(
            &MetaDocument::empty(MetadataLimits::default()),
            &MetadataAccessPolicy::deny_all(),
            &context,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        assert_eq!(
            MetadataReportAdapter::render(
                &snapshot,
                ExperimentalPreviewConfig::disabled(),
                &context,
            ),
            Err(PreviewReportError::Inactive(PreviewReasonCode::Disabled))
        );

        let mismatch = request_context(&RequestContextOptions {
            requested_revision: Some("2"),
            supported_revision: Some("2"),
            ..RequestContextOptions::default()
        })?;
        let mismatch_snapshot = registry.authorize_snapshot(
            &MetaDocument::empty(MetadataLimits::default()),
            &MetadataAccessPolicy::deny_all(),
            &mismatch,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        assert_eq!(
            MetadataReportAdapter::render(
                &mismatch_snapshot,
                ExperimentalPreviewConfig::enabled(),
                &mismatch,
            ),
            Err(PreviewReportError::Inactive(
                PreviewReasonCode::ExactRevisionRequired
            ))
        );
        Ok(())
    }

    #[test]
    fn stale_snapshot_fails_with_a_redacted_error() -> Result<(), Box<dyn std::error::Error>> {
        let context = exact_context()?;
        let registry = registry(&[])?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let snapshot = registry.authorize_snapshot_at(
            &MetaDocument::empty(MetadataLimits::default()),
            &MetadataAccessPolicy::deny_all(),
            &context,
            MetadataSnapshotTtl::from_seconds(1)?,
            now.saturating_sub(2),
        )?;
        assert_eq!(
            MetadataReportAdapter::render_at(
                &snapshot,
                ExperimentalPreviewConfig::enabled(),
                &context,
                now,
            ),
            Err(PreviewReportError::SnapshotUnavailable)
        );
        assert_eq!(
            PreviewReportError::SnapshotUnavailable.to_string(),
            "metadata preview snapshot unavailable"
        );
        Ok(())
    }

    #[test]
    fn report_is_deterministic_bounded_and_explicitly_unstable()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = exact_context()?;
        let registry = registry(&["com.example/zeta", "com.example/alpha"])?;
        let mut document = MetaDocument::empty(MetadataLimits::default());
        registry.insert_owned(
            &mut document,
            &owner()?,
            &key("com.example/zeta")?,
            VersionedMetadataValue::try_new(1, serde_json::json!({"enabled": true}))?,
            &context,
        )?;
        registry.insert_owned(
            &mut document,
            &owner()?,
            &key("com.example/alpha")?,
            VersionedMetadataValue::try_new(1, serde_json::json!({"enabled": false}))?,
            &context,
        )?;
        let snapshot = registry.authorize_snapshot(
            &document,
            &policy(&["com.example/zeta", "com.example/alpha"])?,
            &context,
            MetadataSnapshotTtl::from_seconds(30)?,
        )?;
        let first = MetadataReportAdapter::render(
            &snapshot,
            ExperimentalPreviewConfig::enabled(),
            &context,
        )?;
        let second = MetadataReportAdapter::render(
            &snapshot,
            ExperimentalPreviewConfig::enabled(),
            &context,
        )?;
        assert_eq!(first.body(), second.body());
        assert!(first.body().len() <= HARD_MAX_PREVIEW_REPORT_BYTES);
        assert_eq!(first.preview_revision(), SERVER_METADATA_PREVIEW_REVISION);
        assert_eq!(first.cache_control(), "private, no-store");
        assert_eq!(
            MetadataReportAdapter::route(),
            SERVER_METADATA_PREVIEW_ROUTE
        );

        let body = std::str::from_utf8(first.body())?;
        let alpha = body.find("com.example/alpha").ok_or("alpha key missing")?;
        let zeta = body.find("com.example/zeta").ok_or("zeta key missing")?;
        assert!(alpha < zeta);
        assert!(body.contains("\"stability\":\"unstable\""));
        assert!(body.contains("\"status\":\"experimental\""));
        assert!(body.contains("\"authenticity\":\"server-derived-authorized-registry-snapshot\""));
        assert!(body.contains("\"authorizedSetFingerprint\":\"sha256:"));
        assert!(body.contains("\"evidenceFingerprint\":\"sha256:"));
        assert!(!body.contains("conform"));
        assert!(!body.contains("schema"));
        assert!(!body.contains("server/discover"));
        assert!(!body.contains("example-module"));
        Ok(())
    }
}
