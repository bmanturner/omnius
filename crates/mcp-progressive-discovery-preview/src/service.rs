use std::fmt;

use omnius_mcp_server_core::McpRequestContext;
use thiserror::Error;

use crate::{
    AuthorizedCatalogPort, AuthorizedSnapshotRequest, CapabilityKind, DiscoveryClock,
    DiscoveryEntryMetadata, DiscoveryFilter, DiscoveryLimits, DiscoveryPreviewConfig,
    DiscoveryPreviewReason, DiscoveryPreviewStatus,
    cursor::{CursorCodec, CursorFailure, MAX_CURSOR_TEXT_BYTES},
    model::normalize,
    preview::DiscoveryPreviewDecision,
};

const MAX_QUERY_BYTES: usize = 512;

/// One bounded internal partition/search/page projection request.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryProjectionRequest {
    query: String,
    filter: DiscoveryFilter,
    page_size: u16,
    cursor: Option<String>,
}

impl DiscoveryProjectionRequest {
    /// Creates a request with bounded query and opaque cursor text.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryRequestError`] when the query, page size, or cursor presentation
    /// violates its bound.
    pub fn try_new(
        query: impl Into<String>,
        filter: DiscoveryFilter,
        page_size: u16,
        cursor: Option<String>,
    ) -> Result<Self, DiscoveryRequestError> {
        let query = query.into();
        if query.len() > MAX_QUERY_BYTES
            || query.chars().any(char::is_control)
            || page_size == 0
            || cursor
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_CURSOR_TEXT_BYTES)
        {
            return Err(DiscoveryRequestError);
        }
        Ok(Self {
            query,
            filter,
            page_size,
            cursor,
        })
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "query, filters, and cursor contents are deliberately omitted from diagnostics"
)]
impl fmt::Debug for DiscoveryProjectionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryProjectionRequest")
            .field("page_size", &self.page_size)
            .field("cursor_present", &self.cursor.is_some())
            .finish_non_exhaustive()
    }
}

/// Invalid query, page size, or cursor presentation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid progressive discovery projection request")]
pub struct DiscoveryRequestError;

/// Transport-neutral internal projection over a fresh authorized registry snapshot.
pub struct ProgressiveDiscoveryProjection<P, C> {
    catalog: P,
    clock: C,
    preview: DiscoveryPreviewConfig,
    limits: DiscoveryLimits,
    cursors: CursorCodec,
}

impl<P, C> ProgressiveDiscoveryProjection<P, C>
where
    P: AuthorizedCatalogPort,
    C: DiscoveryClock,
{
    /// Creates a projection with an exact 256-bit cursor-authentication key.
    #[must_use]
    pub fn new(
        catalog: P,
        clock: C,
        preview: DiscoveryPreviewConfig,
        limits: DiscoveryLimits,
        cursor_key: [u8; 32],
    ) -> Self {
        Self {
            catalog,
            clock,
            preview,
            limits,
            cursors: CursorCodec::new(cursor_key),
        }
    }

    /// Produces one compact page after exact preview activation and fresh canonical authorization.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when preview negotiation or request bounds fail, the authorized
    /// snapshot is unavailable, a cursor is invalid or stale, or a bounded internal operation
    /// cannot be completed.
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered flow keeps preview activation, authorization, cursor binding, and bounded projection security gates visible"
    )]
    pub fn project_page(
        &self,
        request_context: &McpRequestContext,
        request: &DiscoveryProjectionRequest,
    ) -> Result<DiscoveryProjectionOutcome, DiscoveryError> {
        if let DiscoveryPreviewDecision::Inactive(reason) = self.preview.evaluate(request_context) {
            return Err(DiscoveryError::new(
                DiscoveryPublicCode::PreviewInactive,
                map_preview_reason(reason),
            ));
        }
        if request.page_size > self.limits.max_page_size() {
            return Err(DiscoveryError::new(
                DiscoveryPublicCode::InvalidRequest,
                DiscoveryReasonCode::PageCeiling,
            ));
        }

        let snapshot = self
            .catalog
            .authorized_snapshot(AuthorizedSnapshotRequest::new(
                request_context,
                self.limits.max_scan_entries(),
            ))
            .map_err(|_| {
                DiscoveryError::new(
                    DiscoveryPublicCode::Unavailable,
                    DiscoveryReasonCode::SnapshotUnavailable,
                )
            })?;
        if snapshot.entries().len() > self.limits.max_scan_entries() {
            return Err(DiscoveryError::new(
                DiscoveryPublicCode::Unavailable,
                DiscoveryReasonCode::SnapshotUnavailable,
            ));
        }

        let now_unix = self.clock.now_unix();
        let normalized_query = normalize(&request.query);
        let fingerprint = snapshot.fingerprint();
        let offset = request.cursor.as_ref().map_or(Ok(0), |cursor| {
            self.cursors.verify(
                cursor,
                now_unix,
                request_context,
                &normalized_query,
                &request.filter,
                request.page_size,
                snapshot.authorization_revision(),
                &fingerprint,
            )
        });
        let offset = offset.map_err(map_cursor_error)?;

        let mut ranked = snapshot
            .entries()
            .iter()
            .filter(|entry| request.filter.matches(entry))
            .filter_map(|entry| entry.rank(&normalized_query).map(|score| (score, entry)))
            .collect::<Vec<_>>();
        ranked.sort_by(|(left_score, left), (right_score, right)| {
            right_score.cmp(left_score).then_with(|| {
                left.capability_id()
                    .cmp(right.capability_id())
                    .then_with(|| left.capability_version().cmp(right.capability_version()))
                    .then_with(|| {
                        left.metadata()
                            .compact()
                            .kind()
                            .cmp(&right.metadata().compact().kind())
                    })
            })
        });
        if offset > ranked.len() {
            return Err(map_cursor_error(CursorFailure::Position));
        }
        let end = offset
            .saturating_add(usize::from(request.page_size))
            .min(ranked.len());
        let hits = ranked[offset..end]
            .iter()
            .map(|(_, entry)| CatalogHit {
                capability_id: entry.capability_id().to_owned(),
                capability_version: entry.capability_version().to_owned(),
                title: entry.title().to_owned(),
                summary: entry.summary().map(str::to_owned),
                metadata: entry.metadata().clone(),
            })
            .collect::<Vec<_>>();
        let next_cursor = if end < ranked.len() {
            let next_offset = u32::try_from(end).map_err(|_| internal_error())?;
            let expires_unix = now_unix
                .checked_add(self.limits.cursor_ttl_seconds())
                .ok_or_else(internal_error)?;
            Some(
                self.cursors
                    .issue(
                        next_offset,
                        expires_unix,
                        request_context,
                        &normalized_query,
                        &request.filter,
                        request.page_size,
                        snapshot.authorization_revision(),
                        &fingerprint,
                    )
                    .map_err(map_cursor_error)?,
            )
        } else {
            None
        };
        let telemetry = DiscoveryTelemetry {
            reason: DiscoveryReasonCode::Served,
            returned_hits: u16::try_from(hits.len()).map_err(|_| internal_error())?,
            cursor_issued: next_cursor.is_some(),
        };
        Ok(DiscoveryProjectionOutcome {
            page: DiscoveryPage { hits, next_cursor },
            telemetry,
            status: self.preview.status(),
        })
    }
}

/// Compact authorized hit for a future settled standard's adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct CatalogHit {
    capability_id: String,
    capability_version: String,
    title: String,
    summary: Option<String>,
    metadata: DiscoveryEntryMetadata,
}

impl CatalogHit {
    /// Returns the canonical capability identifier.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    /// Returns the exact canonical capability version.
    #[must_use]
    pub fn capability_version(&self) -> &str {
        &self.capability_version
    }

    /// Returns the display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns an optional already-authorized summary.
    #[must_use]
    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    /// Returns compact partition, tag, search, capability, and retained future metadata.
    #[must_use]
    pub const fn metadata(&self) -> &DiscoveryEntryMetadata {
        &self.metadata
    }

    /// Returns the compact capability category.
    #[must_use]
    pub const fn kind(&self) -> CapabilityKind {
        self.metadata.compact().kind()
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "authorized hit content is deliberately reduced to its safe capability kind"
)]
impl fmt::Debug for CatalogHit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogHit")
            .field("content", &"[redacted]")
            .field("kind", &self.kind())
            .finish()
    }
}

/// One bounded page. Deliberately omits total, scanned, denied, and unfiltered counts.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryPage {
    hits: Vec<CatalogHit>,
    next_cursor: Option<String>,
}

impl DiscoveryPage {
    /// Returns only authorized hits in deterministic order.
    #[must_use]
    pub fn hits(&self) -> &[CatalogHit] {
        &self.hits
    }

    /// Returns an opaque authenticated cursor when another authorized page exists.
    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "authorized hits and cursor contents are deliberately represented only by counts and presence"
)]
impl fmt::Debug for DiscoveryPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryPage")
            .field("hit_count", &self.hits.len())
            .field("next_cursor_present", &self.next_cursor.is_some())
            .finish()
    }
}

/// Local boundary for adapting a compact authorized page only after a wire contract settles.
pub trait DiscoveryPageAdapter {
    /// Adapter-owned report type.
    type Report;
    /// Adapter-specific rendering failure.
    type Error;

    /// Adapts only the already-authorized bounded page.
    ///
    /// # Errors
    ///
    /// Returns the adapter's [`Self::Error`] when the authorized page cannot be rendered.
    fn adapt(&self, page: &DiscoveryPage) -> Result<Self::Report, Self::Error>;
}

/// Successful internal page projection plus redacted telemetry and explicit preview status.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryProjectionOutcome {
    page: DiscoveryPage,
    telemetry: DiscoveryTelemetry,
    status: DiscoveryPreviewStatus,
}

impl DiscoveryProjectionOutcome {
    /// Returns the bounded page.
    #[must_use]
    pub const fn page(&self) -> &DiscoveryPage {
        &self.page
    }

    /// Returns value-free telemetry dimensions.
    #[must_use]
    pub const fn telemetry(&self) -> DiscoveryTelemetry {
        self.telemetry
    }

    /// Returns the explicit experimental, nonconformant, internal-only status.
    #[must_use]
    pub const fn status(&self) -> DiscoveryPreviewStatus {
        self.status
    }
}

impl fmt::Debug for DiscoveryProjectionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryProjectionOutcome")
            .field("page", &self.page)
            .field("telemetry", &self.telemetry)
            .field("status", &self.status)
            .finish()
    }
}

/// Redacted telemetry for one successful projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryTelemetry {
    /// Value-free reason code.
    pub reason: DiscoveryReasonCode,
    /// Count already visible in this returned page; never a total or denied count.
    pub returned_hits: u16,
    /// Whether this response issued an opaque continuation cursor.
    pub cursor_issued: bool,
}

/// Coarse response-safe failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPublicCode {
    /// Preview activation was absent or rejected.
    PreviewInactive,
    /// Bounded request validation failed.
    InvalidRequest,
    /// Cursor validation failed without disclosing the rejected binding dimension.
    InvalidCursor,
    /// Authorization, snapshot, or internal processing was unavailable.
    Unavailable,
}

/// Value-free internal reason suitable for metrics or structured logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryReasonCode {
    /// A bounded authorized page was returned.
    Served,
    /// Preview configuration is disabled.
    PreviewDisabled,
    /// The exact preview extension was not negotiated.
    PreviewNotNegotiated,
    /// Preview identifier or revision did not exactly match.
    PreviewExactMismatch,
    /// Requested page exceeds the configured ceiling.
    PageCeiling,
    /// Private authorized snapshot was unavailable without disclosing the cause or size.
    SnapshotUnavailable,
    /// Cursor presentation is malformed.
    CursorMalformed,
    /// Cursor expired according to trusted server time.
    CursorExpired,
    /// Cursor integrity or any private binding was rejected without revealing which one.
    CursorRejected,
    /// Internal cursor or time arithmetic failed.
    Internal,
}

impl DiscoveryReasonCode {
    /// Returns a stable telemetry code containing no identity, query, filter, revision, or key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Served => "discovery_served",
            Self::PreviewDisabled => "discovery_preview_disabled",
            Self::PreviewNotNegotiated => "discovery_preview_not_negotiated",
            Self::PreviewExactMismatch => "discovery_preview_exact_mismatch",
            Self::PageCeiling => "discovery_page_ceiling",
            Self::SnapshotUnavailable => "discovery_snapshot_unavailable",
            Self::CursorMalformed => "discovery_cursor_malformed",
            Self::CursorExpired => "discovery_cursor_expired",
            Self::CursorRejected => "discovery_cursor_rejected",
            Self::Internal => "discovery_internal",
        }
    }
}

/// Redacted projection failure. Display output intentionally omits its detailed reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("progressive discovery projection failed")]
pub struct DiscoveryError {
    public_code: DiscoveryPublicCode,
    reason: DiscoveryReasonCode,
}

impl DiscoveryError {
    const fn new(public_code: DiscoveryPublicCode, reason: DiscoveryReasonCode) -> Self {
        Self {
            public_code,
            reason,
        }
    }

    /// Returns the only failure category a transport adapter may expose.
    #[must_use]
    pub const fn public_code(self) -> DiscoveryPublicCode {
        self.public_code
    }

    /// Returns a value-free internal telemetry reason.
    #[must_use]
    pub const fn reason(self) -> DiscoveryReasonCode {
        self.reason
    }
}

const fn map_preview_reason(reason: DiscoveryPreviewReason) -> DiscoveryReasonCode {
    match reason {
        DiscoveryPreviewReason::Disabled => DiscoveryReasonCode::PreviewDisabled,
        DiscoveryPreviewReason::NotNegotiated => DiscoveryReasonCode::PreviewNotNegotiated,
        DiscoveryPreviewReason::ExactMismatch => DiscoveryReasonCode::PreviewExactMismatch,
    }
}

fn map_cursor_error(error: CursorFailure) -> DiscoveryError {
    match error {
        CursorFailure::Malformed => DiscoveryError::new(
            DiscoveryPublicCode::InvalidCursor,
            DiscoveryReasonCode::CursorMalformed,
        ),
        CursorFailure::Expired => DiscoveryError::new(
            DiscoveryPublicCode::InvalidCursor,
            DiscoveryReasonCode::CursorExpired,
        ),
        CursorFailure::Integrity
        | CursorFailure::BindingMismatch
        | CursorFailure::SnapshotMismatch
        | CursorFailure::Position => DiscoveryError::new(
            DiscoveryPublicCode::InvalidCursor,
            DiscoveryReasonCode::CursorRejected,
        ),
        CursorFailure::Internal => internal_error(),
    }
}

const fn internal_error() -> DiscoveryError {
    DiscoveryError::new(
        DiscoveryPublicCode::Unavailable,
        DiscoveryReasonCode::Internal,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use omnius_agent_capability_registry::{
        BudgetBounds, DataPolicyRef, InvocationContext, TenantMode, TraceContext, TraceParent,
    };
    use omnius_auth_core::{
        AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId,
    };
    use omnius_authz_basic::Decision;
    use omnius_core::RequestId;
    use omnius_mcp_server_core::{
        MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
        McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
        McpRequestMetadata,
    };
    use time::{Duration, OffsetDateTime};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        AuthorizationRevision, AuthorizedCatalogSnapshot, CatalogEntry, CompactCapability,
        DiscoveryEntryMetadata, DiscoveryModelError, FutureDiscoveryMetadata,
        PROGRESSIVE_DISCOVERY_PREVIEW_ID, PROGRESSIVE_DISCOVERY_PREVIEW_REVISION,
        ResourceDiscoveryHints,
    };

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl DiscoveryClock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    #[derive(Clone)]
    struct FixedCatalog {
        snapshot: Rc<RefCell<Result<AuthorizedCatalogSnapshot, ()>>>,
        calls: Rc<Cell<usize>>,
        observed_limit: Rc<Cell<usize>>,
    }

    impl FixedCatalog {
        fn set_snapshot(&self, snapshot: AuthorizedCatalogSnapshot) {
            *self.snapshot.borrow_mut() = Ok(snapshot);
        }
    }

    impl AuthorizedCatalogPort for FixedCatalog {
        type Error = ();

        fn authorized_snapshot(
            &self,
            request: AuthorizedSnapshotRequest<'_>,
        ) -> Result<AuthorizedCatalogSnapshot, Self::Error> {
            self.calls.set(self.calls.get() + 1);
            self.observed_limit.set(request.max_entries());
            self.snapshot.borrow().clone()
        }
    }

    fn entry(
        id: &str,
        version: &str,
        kind: CapabilityKind,
    ) -> Result<CatalogEntry, DiscoveryModelError> {
        let (partition, compact) = match kind {
            CapabilityKind::Tool => ("tools", CompactCapability::tool("canonical-result-v1")?),
            CapabilityKind::Resource => (
                "resources",
                CompactCapability::resource(ResourceDiscoveryHints {
                    range_ready: true,
                    hierarchy_ready: true,
                    ..ResourceDiscoveryHints::default()
                }),
            ),
            CapabilityKind::Prompt => ("prompts", CompactCapability::prompt()),
        };
        let metadata = DiscoveryEntryMetadata::try_new(
            partition,
            ["search".to_owned(), "stable".to_owned()],
            ["record lookup".to_owned()],
            compact,
            FutureDiscoveryMetadata::try_new([("future.binary".to_owned(), vec![0, 1, 255])])?,
        )?;
        CatalogEntry::try_new(
            id,
            version,
            format!("{id} Search"),
            Some(format!("find {id} records")),
            metadata,
        )
    }

    fn entries() -> Result<Vec<CatalogEntry>, DiscoveryModelError> {
        Ok(vec![
            entry("tool.beta", "1.0.0", CapabilityKind::Tool)?,
            entry("resource.alpha", "2.0.0", CapabilityKind::Resource)?,
            entry("tool.alpha", "1.1.0", CapabilityKind::Tool)?,
        ])
    }

    fn snapshot(
        authorization_revision: &str,
        entries: Vec<CatalogEntry>,
    ) -> Result<AuthorizedCatalogSnapshot, DiscoveryModelError> {
        AuthorizedCatalogSnapshot::try_new(
            AuthorizationRevision::try_new(authorization_revision)?,
            entries,
        )
    }

    fn catalog(authorization_revision: &str) -> Result<FixedCatalog, DiscoveryModelError> {
        Ok(FixedCatalog {
            snapshot: Rc::new(RefCell::new(Ok(snapshot(
                authorization_revision,
                entries()?,
            )?))),
            calls: Rc::new(Cell::new(0)),
            observed_limit: Rc::new(Cell::new(0)),
        })
    }

    fn service(
        catalog: FixedCatalog,
        now: u64,
        preview: DiscoveryPreviewConfig,
    ) -> Result<ProgressiveDiscoveryProjection<FixedCatalog, FixedClock>, DiscoveryModelError> {
        Ok(ProgressiveDiscoveryProjection::new(
            catalog,
            FixedClock(now),
            preview,
            DiscoveryLimits::try_new(3, 16, 30)?,
            [7_u8; 32],
        ))
    }

    fn request(
        query: &str,
        filter: DiscoveryFilter,
        page_size: u16,
        cursor: Option<String>,
    ) -> Result<DiscoveryProjectionRequest, DiscoveryRequestError> {
        DiscoveryProjectionRequest::try_new(query, filter, page_size, cursor)
    }

    fn extension(revision: &str) -> Result<McpExtension, Box<dyn std::error::Error>> {
        Ok(McpExtension::new(
            McpExtensionId::new(PROGRESSIVE_DISCOVERY_PREVIEW_ID)?,
            McpExtensionRevision::new(revision)?,
        ))
    }

    fn context(
        subject_id: SubjectId,
        tenant_id: TenantId,
        requested_revision: Option<&str>,
        supported_revision: Option<&str>,
    ) -> Result<McpRequestContext, Box<dyn std::error::Error>> {
        let requested = requested_revision.map(extension).transpose()?.into_iter();
        let supported = supported_revision.map(extension).transpose()?.into_iter();
        let metadata = McpRequestMetadata::new(
            MCP_PROTOCOL_REVISION,
            McpClientIdentity::new("progressive-preview-tests", "1")?,
            Vec::new(),
            requested,
            None,
        )?;
        let principal = Principal::new(
            subject_id,
            PrincipalKind::User,
            Some(tenant_id),
            AuthMethod::Session,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal2,
            vec!["catalog.read".parse()?],
        )?;
        let invocation = InvocationContext::new(
            RequestId::new(),
            TraceContext::new(
                "00-00000000000000000000000000000001-0000000000000001-01".parse::<TraceParent>()?,
                None,
            ),
            principal,
            Some(tenant_id),
            Decision::Allow,
            "policy.catalog.r7".parse::<DataPolicyRef>()?,
            BudgetBounds::new(1_024, 1_024, 100)?,
            OffsetDateTime::now_utc() + Duration::hours(1),
            CancellationToken::new(),
        )?;
        let canonical = McpCanonicalContext::new(invocation, TenantMode::Tenant)?;
        Ok(McpRequestContext::new(
            metadata,
            &McpExtensionCatalog::new(supported)?,
            canonical,
        ))
    }

    fn exact_context(
        subject_id: SubjectId,
        tenant_id: TenantId,
    ) -> Result<McpRequestContext, Box<dyn std::error::Error>> {
        context(
            subject_id,
            tenant_id,
            Some(PROGRESSIVE_DISCOVERY_PREVIEW_REVISION),
            Some(PROGRESSIVE_DISCOVERY_PREVIEW_REVISION),
        )
    }

    #[test]
    fn disabled_and_exact_mismatch_fail_before_registry_enumeration()
    -> Result<(), Box<dyn std::error::Error>> {
        let subject = SubjectId::new();
        let tenant = TenantId::new();
        let disabled_catalog = catalog("policy-7")?;
        let disabled_calls = Rc::clone(&disabled_catalog.calls);
        let disabled = service(disabled_catalog, 100, DiscoveryPreviewConfig::disabled())?;
        let projection_request = request("search", DiscoveryFilter::default(), 1, None)?;
        let disabled_error = disabled
            .project_page(&exact_context(subject, tenant)?, &projection_request)
            .err()
            .ok_or("disabled preview returned output")?;
        assert_eq!(
            disabled_error.reason(),
            DiscoveryReasonCode::PreviewDisabled
        );
        assert_eq!(disabled_calls.get(), 0);

        let mismatch_catalog = catalog("policy-7")?;
        let mismatch_calls = Rc::clone(&mismatch_catalog.calls);
        let enabled = service(mismatch_catalog, 100, DiscoveryPreviewConfig::enabled())?;
        let mismatch = context(subject, tenant, Some("2"), Some("1"))?;
        let mismatch_error = enabled
            .project_page(&mismatch, &projection_request)
            .err()
            .ok_or("mismatched revision activated preview")?;
        assert_eq!(
            mismatch_error.reason(),
            DiscoveryReasonCode::PreviewExactMismatch
        );
        assert_eq!(mismatch_calls.get(), 0);

        let absent = context(subject, tenant, None, Some("1"))?;
        let absent_error = enabled
            .project_page(&absent, &projection_request)
            .err()
            .ok_or("unnegotiated preview activated")?;
        assert_eq!(
            absent_error.reason(),
            DiscoveryReasonCode::PreviewNotNegotiated
        );
        assert_eq!(mismatch_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn deterministic_pages_preserve_compact_and_future_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let subject = SubjectId::new();
        let tenant = TenantId::new();
        let context = exact_context(subject, tenant)?;
        let projection = service(catalog("policy-7")?, 100, DiscoveryPreviewConfig::enabled())?;
        let first_request = request("search", DiscoveryFilter::default(), 2, None)?;
        let first = projection.project_page(&context, &first_request)?;
        let repeated = projection.project_page(&context, &first_request)?;
        let ids = first
            .page()
            .hits()
            .iter()
            .map(CatalogHit::capability_id)
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["resource.alpha", "tool.alpha"]);
        assert_eq!(first, repeated);
        assert_eq!(
            first.status(),
            DiscoveryPreviewStatus::ExperimentalNonconformantInternalProjection
        );
        let compact = &first.page().hits()[0];
        assert_eq!(compact.capability_version(), "2.0.0");
        assert_eq!(compact.metadata().tags().len(), 2);
        assert_eq!(compact.metadata().search_terms().len(), 1);
        assert_eq!(
            compact.metadata().future().fields()["future.binary"],
            vec![0, 1, 255]
        );

        let second = projection.project_page(
            &context,
            &request(
                "search",
                DiscoveryFilter::default(),
                2,
                first.page().next_cursor().map(str::to_owned),
            )?,
        )?;
        assert_eq!(second.page().hits()[0].capability_id(), "tool.beta");
        assert!(second.page().next_cursor().is_none());
        Ok(())
    }

    #[test]
    fn cursor_rejects_cross_context_tampering_forgery_and_expiry_without_dimension_leakage()
    -> Result<(), Box<dyn std::error::Error>> {
        let subject = SubjectId::new();
        let tenant = TenantId::new();
        let exact = exact_context(subject, tenant)?;
        let base_catalog = catalog("policy-7")?;
        let projection = service(base_catalog, 100, DiscoveryPreviewConfig::enabled())?;
        let first = projection.project_page(
            &exact,
            &request("search", DiscoveryFilter::default(), 1, None)?,
        )?;
        let cursor = first
            .page()
            .next_cursor()
            .ok_or("missing cursor")?
            .to_owned();

        let mut forged = cursor.clone().into_bytes();
        forged[0] = if forged[0] == b'A' { b'B' } else { b'A' };
        let forged = String::from_utf8(forged)?;
        let forged_error = projection
            .project_page(
                &exact,
                &request("search", DiscoveryFilter::default(), 1, Some(forged))?,
            )
            .err()
            .ok_or("forged cursor accepted")?;
        assert_eq!(forged_error.reason(), DiscoveryReasonCode::CursorRejected);

        let other_principal = exact_context(SubjectId::new(), tenant)?;
        let other_tenant = TenantId::new();
        let other_tenant_context = exact_context(subject, other_tenant)?;
        let changed_filter =
            DiscoveryFilter::try_new(["tools".to_owned()], Vec::new(), Vec::new())?;
        let cases = [
            (&other_principal, "search", DiscoveryFilter::default(), 1),
            (
                &other_tenant_context,
                "search",
                DiscoveryFilter::default(),
                1,
            ),
            (&exact, "changed", DiscoveryFilter::default(), 1),
            (&exact, "search", changed_filter, 1),
            (&exact, "search", DiscoveryFilter::default(), 2),
        ];
        for (request_context, query, filter, page_size) in cases {
            let error = projection
                .project_page(
                    request_context,
                    &request(query, filter, page_size, Some(cursor.clone()))?,
                )
                .err()
                .ok_or("cross-binding cursor accepted")?;
            assert_eq!(error.public_code(), DiscoveryPublicCode::InvalidCursor);
            assert_eq!(error.reason(), DiscoveryReasonCode::CursorRejected);
        }

        let expired = service(catalog("policy-7")?, 130, DiscoveryPreviewConfig::enabled())?;
        let expired_error = expired
            .project_page(
                &exact,
                &request("search", DiscoveryFilter::default(), 1, Some(cursor))?,
            )
            .err()
            .ok_or("expired cursor accepted")?;
        assert_eq!(expired_error.reason(), DiscoveryReasonCode::CursorExpired);
        Ok(())
    }

    #[test]
    fn cursor_rejects_fresh_authorized_set_change_with_reused_adapter_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let subject = SubjectId::new();
        let tenant = TenantId::new();
        let context = exact_context(subject, tenant)?;
        let mutable_catalog = catalog("reused-policy-revision")?;
        let projection = service(
            mutable_catalog.clone(),
            100,
            DiscoveryPreviewConfig::enabled(),
        )?;
        let first = projection.project_page(
            &context,
            &request("search", DiscoveryFilter::default(), 1, None)?,
        )?;
        let cursor = first
            .page()
            .next_cursor()
            .ok_or("missing cursor")?
            .to_owned();

        let revised_authorization = service(
            catalog("policy-revision-advanced")?,
            100,
            DiscoveryPreviewConfig::enabled(),
        )?;
        let revision_error = revised_authorization
            .project_page(
                &context,
                &request(
                    "search",
                    DiscoveryFilter::default(),
                    1,
                    Some(cursor.clone()),
                )?,
            )
            .err()
            .ok_or("changed authorization revision accepted")?;
        assert_eq!(revision_error.reason(), DiscoveryReasonCode::CursorRejected);

        let mut changed = entries()?;
        changed.push(entry(
            "tool.newly-authorized",
            "1.0.0",
            CapabilityKind::Tool,
        )?);
        mutable_catalog.set_snapshot(snapshot("reused-policy-revision", changed)?);
        let error = projection
            .project_page(
                &context,
                &request("search", DiscoveryFilter::default(), 1, Some(cursor))?,
            )
            .err()
            .ok_or("stale snapshot cursor accepted")?;
        assert_eq!(error.public_code(), DiscoveryPublicCode::InvalidCursor);
        assert_eq!(error.reason(), DiscoveryReasonCode::CursorRejected);
        Ok(())
    }

    #[test]
    fn surface_is_internal_only_and_owns_no_proprietary_rpc_name() {
        let config = DiscoveryPreviewConfig::enabled();
        assert_eq!(
            config.status(),
            DiscoveryPreviewStatus::ExperimentalNonconformantInternalProjection
        );
        assert!(!PROGRESSIVE_DISCOVERY_PREVIEW_ID.contains('/'));
    }
}
