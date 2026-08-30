use omnius_llm_core::RawRetentionPolicy;
use omnius_llm_prompt_catalog::{AssembledContext, ProviderCacheAdmission, TruncationReason};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ArtifactKind, DataClassification};

/// Closed reason codes safe for metrics, logs, and audit records.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SafetyReasonCode {
    /// Default telemetry and provider retention exclude content.
    DefaultContentExcluded,
    /// Complete diagnostic evidence admitted bounded raw retention.
    DiagnosticCaptureAdmitted,
    /// Diagnostic authorization evidence was absent.
    DiagnosticAuthorizationMissing,
    /// Authoritative policy denied diagnostic capture.
    DiagnosticAuthorizationDenied,
    /// Diagnostic expiry evidence was absent or invalid.
    DiagnosticExpiryInvalid,
    /// Diagnostic sample evidence was absent or invalid.
    DiagnosticSamplingInvalid,
    /// Diagnostic encryption evidence was absent.
    DiagnosticEncryptionMissing,
    /// Diagnostic audit evidence was absent.
    DiagnosticAuditMissing,
    /// Untrusted data was proposed for a privileged instruction channel.
    UntrustedContentCannotBeInstruction,
    /// Prompt-injection assessment was missing.
    InjectionAssessmentMissing,
    /// A prompt-injection indicator imposed additional restrictions.
    InjectionIndicatorRestricted,
    /// No canonical registry capability accompanied a proposed tool call.
    ToolAuthorityMissing,
    /// Tool side-effect and confirmation metadata were inconsistent.
    ToolPolicyAmbiguous,
    /// Registry confirmation evidence did not satisfy the side-effect policy.
    SideEffectConfirmationRequired,
    /// No authoritative server egress decision accompanied the request.
    EgressAuthorityMissing,
    /// Authoritative server policy denied egress.
    EgressDeniedByServerPolicy,
    /// Every authorized context record fit the deterministic budget.
    ContextFullySelected,
    /// Deterministic context selection stopped at the record-count boundary.
    ContextTruncatedRecordCount,
    /// Deterministic context selection stopped at the per-record byte boundary.
    ContextTruncatedRecordBytes,
    /// Deterministic context selection stopped at the total-byte boundary.
    ContextTruncatedTotalBytes,
    /// Deterministic context selection stopped at the token-estimate boundary.
    ContextTruncatedEstimatedTokens,
    /// Route policy explicitly disabled provider prompt caching.
    ProviderCacheDisabled,
    /// Preferred provider prompt caching lacked exact capability evidence.
    ProviderCacheUnavailable,
    /// Exact provider capability evidence admitted explicit prompt-cache controls.
    ProviderCacheEnabled,
    /// A complete deletion or retention fan-out was planned.
    InventoryFanoutPlanned,
    /// An inventory adapter returned valid content-free evidence.
    InventoryAdapterSucceeded,
    /// An inventory adapter returned a closed failure.
    InventoryAdapterFailed,
    /// A revision fence recognized an exact idempotent replay.
    InventoryFenceReplay,
    /// A revision fence rejected stale work.
    InventoryFenceStale,
}

/// Closed safety events emitted to the application audit adapter.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SafetyAuditEvent {
    /// A request data-handling policy was applied.
    DataPolicyApplied,
    /// Diagnostic capture admission completed.
    DiagnosticCaptureDecision,
    /// Instruction/data boundary evaluation completed.
    InstructionBoundaryDecision,
    /// Tool, egress, or confirmation restrictions were computed.
    ExecutionRestriction,
    /// Deterministic context ordering and truncation completed.
    ContextAssemblyDecision,
    /// Explicit provider prompt-cache admission completed.
    ProviderCacheDecision,
    /// Deletion or retention fan-out was planned.
    InventoryFanoutPlanned,
    /// One inventory adapter attempt completed.
    InventoryAdapterOutcome,
    /// One inventory revision fence was evaluated.
    InventoryFenceDecision,
}

/// Content-free facts supplied to the application audit adapter.
///
/// Request, tenant, principal, prompt, response, reasoning, schema, credential,
/// and provider values are intentionally not representable here. The audit adapter
/// adds its own authenticated correlation envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyAuditFact {
    event: SafetyAuditEvent,
    reason: SafetyReasonCode,
    artifact: Option<ArtifactKind>,
    classification: Option<DataClassification>,
    raw_retention: Option<RawRetentionPolicy>,
}

impl SafetyAuditFact {
    /// Creates a value-free audit fact.
    #[must_use]
    pub const fn new(event: SafetyAuditEvent, reason: SafetyReasonCode) -> Self {
        Self {
            event,
            reason,
            artifact: None,
            classification: None,
            raw_retention: None,
        }
    }

    /// Adds one closed artifact category and classification.
    #[must_use]
    pub const fn with_artifact(
        mut self,
        artifact: ArtifactKind,
        classification: DataClassification,
    ) -> Self {
        self.artifact = Some(artifact);
        self.classification = Some(classification);
        self
    }

    /// Adds only the effective raw-retention category.
    #[must_use]
    pub const fn with_raw_retention(mut self, raw_retention: RawRetentionPolicy) -> Self {
        self.raw_retention = Some(raw_retention);
        self
    }

    /// Returns the closed event.
    #[must_use]
    pub const fn event(self) -> SafetyAuditEvent {
        self.event
    }

    /// Returns the closed reason code.
    #[must_use]
    pub const fn reason(self) -> SafetyReasonCode {
        self.reason
    }

    /// Returns the optional artifact category.
    #[must_use]
    pub const fn artifact(self) -> Option<ArtifactKind> {
        self.artifact
    }

    /// Returns the optional classification.
    #[must_use]
    pub const fn classification(self) -> Option<DataClassification> {
        self.classification
    }

    /// Returns the optional effective raw-retention category.
    #[must_use]
    pub const fn raw_retention(self) -> Option<RawRetentionPolicy> {
        self.raw_retention
    }

    /// Sends the fact to an application audit adapter that can only receive closed facts.
    ///
    /// # Errors
    ///
    /// Returns the adapter's content-free failure.
    pub fn write_audit<A>(self, adapter: &A) -> Result<(), A::Error>
    where
        A: SafetyAuditAdapter,
    {
        adapter.record(self)
    }

    /// Records the fact as a fixed-cardinality metric without accepting request identifiers or content.
    pub fn record_default_metrics(self) {
        metrics::counter!(
            "omnius_llm_safety_events_total",
            "event" => self.event.as_str(),
            "reason" => self.reason.as_str(),
            "artifact" => self.artifact.map_or("none", artifact_label),
            "classification" => self.classification.map_or("none", classification_label),
            "raw_retention" => self.raw_retention.map_or("none", raw_retention_label),
        )
        .increment(1);
    }
}

impl SafetyReasonCode {
    /// Returns the fixed label used by audit and telemetry adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultContentExcluded => "default_content_excluded",
            Self::DiagnosticCaptureAdmitted => "diagnostic_capture_admitted",
            Self::DiagnosticAuthorizationMissing => "diagnostic_authorization_missing",
            Self::DiagnosticAuthorizationDenied => "diagnostic_authorization_denied",
            Self::DiagnosticExpiryInvalid => "diagnostic_expiry_invalid",
            Self::DiagnosticSamplingInvalid => "diagnostic_sampling_invalid",
            Self::DiagnosticEncryptionMissing => "diagnostic_encryption_missing",
            Self::DiagnosticAuditMissing => "diagnostic_audit_missing",
            Self::UntrustedContentCannotBeInstruction => "untrusted_content_cannot_be_instruction",
            Self::InjectionAssessmentMissing => "injection_assessment_missing",
            Self::InjectionIndicatorRestricted => "injection_indicator_restricted",
            Self::ToolAuthorityMissing => "tool_authority_missing",
            Self::ToolPolicyAmbiguous => "tool_policy_ambiguous",
            Self::SideEffectConfirmationRequired => "side_effect_confirmation_required",
            Self::EgressAuthorityMissing => "egress_authority_missing",
            Self::EgressDeniedByServerPolicy => "egress_denied_by_server_policy",
            Self::ContextFullySelected => "context_fully_selected",
            Self::ContextTruncatedRecordCount => "context_truncated_record_count",
            Self::ContextTruncatedRecordBytes => "context_truncated_record_bytes",
            Self::ContextTruncatedTotalBytes => "context_truncated_total_bytes",
            Self::ContextTruncatedEstimatedTokens => "context_truncated_estimated_tokens",
            Self::ProviderCacheDisabled => "provider_cache_disabled",
            Self::ProviderCacheUnavailable => "provider_cache_unavailable",
            Self::ProviderCacheEnabled => "provider_cache_enabled",
            Self::InventoryFanoutPlanned => "inventory_fanout_planned",
            Self::InventoryAdapterSucceeded => "inventory_adapter_succeeded",
            Self::InventoryAdapterFailed => "inventory_adapter_failed",
            Self::InventoryFenceReplay => "inventory_fence_replay",
            Self::InventoryFenceStale => "inventory_fence_stale",
        }
    }
}

impl SafetyAuditEvent {
    /// Returns the fixed event name used by audit and telemetry adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataPolicyApplied => "data_policy_applied",
            Self::DiagnosticCaptureDecision => "diagnostic_capture_decision",
            Self::InstructionBoundaryDecision => "instruction_boundary_decision",
            Self::ExecutionRestriction => "execution_restriction",
            Self::ContextAssemblyDecision => "context_assembly_decision",
            Self::ProviderCacheDecision => "provider_cache_decision",
            Self::InventoryFanoutPlanned => "inventory_fanout_planned",
            Self::InventoryAdapterOutcome => "inventory_adapter_outcome",
            Self::InventoryFenceDecision => "inventory_fence_decision",
        }
    }
}

/// Application-owned audit port restricted to content-free safety facts.
///
/// The application adds authenticated request, tenant, and principal correlation outside
/// this crate. Those identifiers can never be supplied through [`SafetyAuditFact`].
pub trait SafetyAuditAdapter {
    /// Content-free adapter failure.
    type Error;

    /// Records one closed safety fact.
    ///
    /// # Errors
    ///
    /// Returns a content-free adapter failure.
    fn record(&self, fact: SafetyAuditFact) -> Result<(), Self::Error>;
}

/// Closed deterministic context-truncation outcome safe for logs and metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextTruncationOutcome {
    /// Every authorized record fit.
    None,
    /// The record-count budget stopped prefix selection.
    RecordCount,
    /// The per-record byte limit stopped prefix selection.
    RecordBytes,
    /// The total-byte budget stopped prefix selection.
    TotalBytes,
    /// The token-estimate budget stopped prefix selection.
    EstimatedTokens,
}

impl ContextTruncationOutcome {
    /// Returns the fixed telemetry label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RecordCount => "record_count",
            Self::RecordBytes => "record_bytes",
            Self::TotalBytes => "total_bytes",
            Self::EstimatedTokens => "estimated_tokens",
        }
    }

    const fn reason_code(self) -> SafetyReasonCode {
        match self {
            Self::None => SafetyReasonCode::ContextFullySelected,
            Self::RecordCount => SafetyReasonCode::ContextTruncatedRecordCount,
            Self::RecordBytes => SafetyReasonCode::ContextTruncatedRecordBytes,
            Self::TotalBytes => SafetyReasonCode::ContextTruncatedTotalBytes,
            Self::EstimatedTokens => SafetyReasonCode::ContextTruncatedEstimatedTokens,
        }
    }
}

/// Identifier-free observable facts for deterministic context selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentFreeContextFacts {
    selected_records: usize,
    selected_bytes: usize,
    estimated_tokens: usize,
    omitted_records: usize,
    truncation: ContextTruncationOutcome,
}

impl ContentFreeContextFacts {
    /// Projects a context manifest into bounded counts without provenance identifiers or content.
    #[must_use]
    pub fn from_context(context: &AssembledContext) -> Self {
        let manifest = context.manifest();
        Self {
            selected_records: manifest.ordered_provenance().len(),
            selected_bytes: manifest.selected_bytes(),
            estimated_tokens: manifest.estimated_tokens(),
            omitted_records: manifest.omitted_records(),
            truncation: match manifest.truncation_reason() {
                None => ContextTruncationOutcome::None,
                Some(TruncationReason::RecordCount) => ContextTruncationOutcome::RecordCount,
                Some(TruncationReason::RecordBytes) => ContextTruncationOutcome::RecordBytes,
                Some(TruncationReason::TotalBytes) => ContextTruncationOutcome::TotalBytes,
                Some(TruncationReason::EstimatedTokens) => {
                    ContextTruncationOutcome::EstimatedTokens
                }
            },
        }
    }

    /// Returns the number of records in the selected deterministic prefix.
    #[must_use]
    pub const fn selected_records(self) -> usize {
        self.selected_records
    }

    /// Returns the selected UTF-8 byte count.
    #[must_use]
    pub const fn selected_bytes(self) -> usize {
        self.selected_bytes
    }

    /// Returns the deterministic conservative token estimate.
    #[must_use]
    pub const fn estimated_tokens(self) -> usize {
        self.estimated_tokens
    }

    /// Returns the count excluded after the deterministic prefix boundary.
    #[must_use]
    pub const fn omitted_records(self) -> usize {
        self.omitted_records
    }

    /// Returns the closed truncation outcome.
    #[must_use]
    pub const fn truncation(self) -> ContextTruncationOutcome {
        self.truncation
    }

    /// Converts the truncation result into a content-free application audit fact.
    #[must_use]
    pub const fn audit_fact(self) -> SafetyAuditFact {
        SafetyAuditFact::new(
            SafetyAuditEvent::ContextAssemblyDecision,
            self.truncation.reason_code(),
        )
    }

    /// Records fixed-cardinality truncation metrics without authorization or provenance identifiers.
    pub fn record_default_metrics(self) {
        metrics::counter!(
            "omnius_llm_context_assemblies_total",
            "truncation" => self.truncation.as_str(),
        )
        .increment(1);
        metrics::counter!("omnius_llm_context_records_selected_total")
            .increment(count_as_u64(self.selected_records));
        metrics::counter!("omnius_llm_context_records_omitted_total")
            .increment(count_as_u64(self.omitted_records));
        metrics::counter!("omnius_llm_context_bytes_selected_total")
            .increment(count_as_u64(self.selected_bytes));
        metrics::counter!("omnius_llm_context_tokens_estimated_total")
            .increment(count_as_u64(self.estimated_tokens));
    }
}

/// Closed provider prompt-cache outcome derived from explicit capability admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCacheOutcome {
    /// Route policy explicitly disabled provider caching.
    Disabled,
    /// Preferred caching lacked exact prompt-cache and cache-control evidence.
    Unavailable,
    /// Evidence-backed provider controls were admitted.
    Enabled,
}

impl ProviderCacheOutcome {
    /// Returns the fixed telemetry label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
            Self::Enabled => "enabled",
        }
    }

    const fn reason_code(self) -> SafetyReasonCode {
        match self {
            Self::Disabled => SafetyReasonCode::ProviderCacheDisabled,
            Self::Unavailable => SafetyReasonCode::ProviderCacheUnavailable,
            Self::Enabled => SafetyReasonCode::ProviderCacheEnabled,
        }
    }
}

/// Identifier-free facts projected from provider prompt-cache admission.
///
/// An enabled value can only be obtained from [`ProviderCacheAdmission::Enabled`],
/// whose controls require exact provider/model capability evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentFreeProviderCacheFacts {
    outcome: ProviderCacheOutcome,
    ttl_seconds: Option<u64>,
    breakpoint_count: usize,
}

impl ContentFreeProviderCacheFacts {
    /// Projects typed provider-cache admission without retaining model identity or evidence digests.
    #[must_use]
    pub fn from_admission(admission: &ProviderCacheAdmission) -> Self {
        match admission {
            ProviderCacheAdmission::Disabled => Self {
                outcome: ProviderCacheOutcome::Disabled,
                ttl_seconds: None,
                breakpoint_count: 0,
            },
            ProviderCacheAdmission::Unavailable => Self {
                outcome: ProviderCacheOutcome::Unavailable,
                ttl_seconds: None,
                breakpoint_count: 0,
            },
            ProviderCacheAdmission::Enabled(controls) => Self {
                outcome: ProviderCacheOutcome::Enabled,
                ttl_seconds: Some(controls.ttl_seconds()),
                breakpoint_count: controls.breakpoints().len(),
            },
        }
    }

    /// Returns the closed admission outcome.
    #[must_use]
    pub const fn outcome(self) -> ProviderCacheOutcome {
        self.outcome
    }

    /// Returns the explicit admitted TTL when controls are enabled.
    #[must_use]
    pub const fn ttl_seconds(self) -> Option<u64> {
        self.ttl_seconds
    }

    /// Returns the number of explicit admitted cache breakpoints.
    #[must_use]
    pub const fn breakpoint_count(self) -> usize {
        self.breakpoint_count
    }

    /// Converts the provider-cache decision into a content-free application audit fact.
    #[must_use]
    pub const fn audit_fact(self) -> SafetyAuditFact {
        SafetyAuditFact::new(
            SafetyAuditEvent::ProviderCacheDecision,
            self.outcome.reason_code(),
        )
    }

    /// Records a fixed-cardinality provider-cache decision metric without model identifiers.
    pub fn record_default_metrics(self) {
        metrics::counter!(
            "omnius_llm_provider_cache_decisions_total",
            "outcome" => self.outcome.as_str(),
        )
        .increment(1);
        metrics::counter!(
            "omnius_llm_provider_cache_breakpoints_admitted_total",
            "outcome" => self.outcome.as_str(),
        )
        .increment(count_as_u64(self.breakpoint_count));
    }
}

const fn artifact_label(artifact: ArtifactKind) -> &'static str {
    match artifact {
        ArtifactKind::Prompt => "prompt",
        ArtifactKind::Response => "response",
        ArtifactKind::ToolArguments => "tool_arguments",
        ArtifactKind::Citation => "citation",
        ArtifactKind::File => "file",
        ArtifactKind::OpaqueReasoning => "opaque_reasoning",
    }
}

const fn classification_label(classification: DataClassification) -> &'static str {
    match classification {
        DataClassification::Public => "public",
        DataClassification::Internal => "internal",
        DataClassification::Confidential => "confidential",
        DataClassification::Restricted => "restricted",
    }
}

const fn raw_retention_label(retention: RawRetentionPolicy) -> &'static str {
    match retention {
        RawRetentionPolicy::Discard => "discard",
        RawRetentionPolicy::Redacted => "redacted",
        RawRetentionPolicy::Full => "full",
    }
}

fn count_as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
