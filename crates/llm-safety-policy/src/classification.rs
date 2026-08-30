use std::fmt;

use omnius_llm_core::RawRetentionPolicy;
pub use omnius_llm_prompt_catalog::DataClassification;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{DiagnosticAdmissionError, DiagnosticCaptureAdmission, DiagnosticCaptureRequest};

const CLASSIFICATION_COUNT: usize = 4;

/// Independently classified artifact categories on every LLM request.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// User, system, and developer prompt material.
    Prompt,
    /// Canonical model response material.
    Response,
    /// Arguments proposed for capability invocation.
    ToolArguments,
    /// Citations and their quoted or linked material.
    Citation,
    /// Uploaded, generated, or referenced file material.
    File,
    /// Provider-owned opaque reasoning state.
    OpaqueReasoning,
}

impl ArtifactKind {
    /// Every required artifact category in stable order.
    pub const ALL: [Self; 6] = [
        Self::Prompt,
        Self::Response,
        Self::ToolArguments,
        Self::Citation,
        Self::File,
        Self::OpaqueReasoning,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Prompt => 0,
            Self::Response => 1,
            Self::ToolArguments => 2,
            Self::Citation => 3,
            Self::File => 4,
            Self::OpaqueReasoning => 5,
        }
    }
}

/// Complete classification matrix for one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactClassifications([DataClassification; ArtifactKind::ALL.len()]);

impl ArtifactClassifications {
    /// Creates a complete matrix without deriving one artifact's classification from another.
    #[must_use]
    pub const fn new(
        prompt: DataClassification,
        response: DataClassification,
        tool_arguments: DataClassification,
        citation: DataClassification,
        file: DataClassification,
        opaque_reasoning: DataClassification,
    ) -> Self {
        Self([
            prompt,
            response,
            tool_arguments,
            citation,
            file,
            opaque_reasoning,
        ])
    }

    /// Returns the independently configured classification for an artifact category.
    #[must_use]
    pub const fn classification(self, artifact: ArtifactKind) -> DataClassification {
        self.0[artifact.index()]
    }

    /// Returns a new matrix changing exactly one artifact category.
    #[must_use]
    pub const fn with_classification(
        mut self,
        artifact: ArtifactKind,
        classification: DataClassification,
    ) -> Self {
        self.0[artifact.index()] = classification;
        self
    }

    /// Verifies that every artifact fits an independently selected route ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactPolicyError`] without revealing which content crossed the ceiling.
    pub fn validate_maximum(self, maximum: DataClassification) -> Result<(), ArtifactPolicyError> {
        if self
            .0
            .into_iter()
            .any(|classification| classification > maximum)
        {
            Err(ArtifactPolicyError::ClassificationExceedsRouteMaximum)
        } else {
            Ok(())
        }
    }
}

/// Closed artifact-policy admission failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ArtifactPolicyError {
    /// At least one independently classified artifact exceeds the selected route ceiling.
    #[error("artifact classification exceeds the selected route maximum")]
    ClassificationExceedsRouteMaximum,
}
/// The only telemetry mode exposed by the safety policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryPolicy;

impl TelemetryPolicy {
    /// Reports that prompt, response, reasoning, tool, citation, and file content is excluded.
    #[must_use]
    pub const fn includes_content(self) -> bool {
        false
    }
}

/// Closed per-request data-handling policy.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DataHandlingPolicy {
    classifications: ArtifactClassifications,
    telemetry: TelemetryPolicy,
    raw_retention: RawRetentionPolicy,
    diagnostic_expires_at: Option<OffsetDateTime>,
}

impl DataHandlingPolicy {
    /// Creates the default content-free policy with no retained provider payload.
    #[must_use]
    pub const fn new(classifications: ArtifactClassifications) -> Self {
        Self {
            classifications,
            telemetry: TelemetryPolicy,
            raw_retention: RawRetentionPolicy::Discard,
            diagnostic_expires_at: None,
        }
    }

    /// Returns the complete independent classification matrix.
    #[must_use]
    pub const fn classifications(self) -> ArtifactClassifications {
        self.classifications
    }

    /// Returns the telemetry policy, which never includes artifact content.
    #[must_use]
    pub const fn telemetry(self) -> TelemetryPolicy {
        self.telemetry
    }

    /// Returns the effective provider raw-retention policy at one explicit instant.
    ///
    /// Full diagnostic retention fails back to discard at its admitted expiry.
    #[must_use]
    pub fn raw_retention_at(&self, now: OffsetDateTime) -> RawRetentionPolicy {
        if self.raw_retention == RawRetentionPolicy::Full
            && self
                .diagnostic_expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            RawRetentionPolicy::Discard
        } else {
            self.raw_retention
        }
    }

    /// Enables only the content-free structural raw summary supported by `llm-core`.
    #[must_use]
    pub const fn with_redacted_raw_summary(mut self) -> Self {
        self.raw_retention = RawRetentionPolicy::Redacted;
        self.diagnostic_expires_at = None;
        self
    }

    /// Applies full raw retention only after complete diagnostic-capture admission.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticAdmissionError`] without modifying the policy when any
    /// authorization, expiry, sampling, encryption, or audit condition fails.
    pub fn with_diagnostic_capture(
        mut self,
        admission: &DiagnosticCaptureAdmission,
        request: &DiagnosticCaptureRequest,
        now: OffsetDateTime,
    ) -> Result<Self, DiagnosticAdmissionError> {
        self.raw_retention = admission.effective_raw_retention(request, now)?;
        self.diagnostic_expires_at = request.expires_at();
        Ok(self)
    }
}

impl fmt::Debug for DataHandlingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataHandlingPolicy")
            .field("classifications", &self.classifications)
            .field("telemetry", &self.telemetry)
            .field("raw_retention", &self.raw_retention)
            .field(
                "diagnostic_expiry_present",
                &self.diagnostic_expires_at.is_some(),
            )
            .finish()
    }
}

/// Content-free facts suitable for default metrics and structured logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentFreeTelemetryFacts {
    classification_counts: [u32; CLASSIFICATION_COUNT],
    raw_retention: RawRetentionPolicy,
}

impl ContentFreeTelemetryFacts {
    /// Derives bounded telemetry facts without accepting any artifact content.
    #[must_use]
    pub fn from_policy(policy: DataHandlingPolicy, now: OffsetDateTime) -> Self {
        let mut classification_counts = [0_u32; CLASSIFICATION_COUNT];
        for artifact in ArtifactKind::ALL {
            let index = classification_index(policy.classifications.classification(artifact));
            classification_counts[index] += 1;
        }
        Self {
            classification_counts,
            raw_retention: policy.raw_retention_at(now),
        }
    }

    /// Returns how many artifact categories use one classification.
    #[must_use]
    pub const fn artifact_count(self, classification: DataClassification) -> u32 {
        self.classification_counts[classification_index(classification)]
    }

    /// Returns the effective raw-retention category without payload content.
    #[must_use]
    pub const fn raw_retention(self) -> RawRetentionPolicy {
        self.raw_retention
    }

    /// Records fixed-cardinality policy metrics without accepting artifact content or identifiers.
    pub fn record_default_metrics(self) {
        for classification in [
            DataClassification::Public,
            DataClassification::Internal,
            DataClassification::Confidential,
            DataClassification::Restricted,
        ] {
            metrics::counter!(
                "omnius_llm_artifact_classifications_total",
                "classification" => classification_label(classification),
            )
            .increment(u64::from(self.artifact_count(classification)));
        }
        metrics::counter!(
            "omnius_llm_data_handling_policies_total",
            "raw_retention" => raw_retention_label(self.raw_retention),
        )
        .increment(1);
    }
}

const fn classification_index(classification: DataClassification) -> usize {
    match classification {
        DataClassification::Public => 0,
        DataClassification::Internal => 1,
        DataClassification::Confidential => 2,
        DataClassification::Restricted => 3,
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
