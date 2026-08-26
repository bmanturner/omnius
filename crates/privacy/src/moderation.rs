use std::sync::Arc;

use rsk_auth_core::{SubjectId, TenantId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    ActorIdentity, EvidenceDigest, ObjectReference, PolicyVersion, ReasonCode,
    types::privacy_uuid_id,
};

privacy_uuid_id!(ReportId, "A durable moderation report identity.");
privacy_uuid_id!(
    EvidenceId,
    "An immutable moderation evidence-reference identity."
);
privacy_uuid_id!(
    ModerationActionId,
    "An immutable moderation action identity."
);
privacy_uuid_id!(AppealId, "A durable moderation appeal identity.");
privacy_uuid_id!(AppealDecisionId, "An immutable appeal-decision identity.");

/// Durable report workflow state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportState {
    /// Newly submitted and awaiting review.
    Submitted,
    /// A moderator has claimed review.
    UnderReview,
    /// A moderation action was recorded.
    Actioned,
    /// The report was dismissed by an explicit action.
    Dismissed,
    /// The subject appealed an action.
    Appealed,
    /// Appeal or policy review reached a terminal result.
    Resolved,
}

impl ReportState {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "submitted" => Some(Self::Submitted),
            "under_review" => Some(Self::UnderReview),
            "actioned" => Some(Self::Actioned),
            "dismissed" => Some(Self::Dismissed),
            "appealed" => Some(Self::Appealed),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// Command to submit a product moderation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitReport {
    /// Tenant containing reporter and subject.
    pub tenant_id: TenantId,
    /// Subject being reported.
    pub subject_id: SubjectId,
    /// Product-local, bounded report reason.
    pub reason_code: ReasonCode,
    /// Exact policy revision used for the report.
    pub policy_version: PolicyVersion,
}

/// Durable moderation report without raw report text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModerationReport {
    /// Report identity.
    pub id: ReportId,
    /// Tenant containing the report.
    pub tenant_id: TenantId,
    /// Authenticated reporter.
    pub reporter_subject_id: SubjectId,
    /// Subject being reported.
    pub subject_id: SubjectId,
    /// Product-local reason code.
    pub reason_code: ReasonCode,
    /// Governing policy revision.
    pub policy_version: PolicyVersion,
    /// Durable workflow state.
    pub state: ReportState,
    /// Optimistic state revision.
    pub version: u64,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last transition time.
    pub updated_at: OffsetDateTime,
}

/// Closed class of externally retained evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Content artifact.
    Content,
    /// Account-state snapshot.
    Account,
    /// Message artifact.
    Message,
    /// Generic application object.
    Object,
    /// Provider-produced signed or hashed attestation.
    ProviderAttestation,
}

impl EvidenceKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Account => "account",
            Self::Message => "message",
            Self::Object => "object",
            Self::ProviderAttestation => "provider_attestation",
        }
    }
}

/// Command to attach only a digest and opaque reference to moderation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddModerationEvidence {
    /// Report receiving the evidence.
    pub report_id: ReportId,
    /// Expected tenant, preventing cross-tenant identifier use.
    pub tenant_id: TenantId,
    /// Appeal receiving the evidence, or `None` for report-level evidence.
    pub appeal_id: Option<AppealId>,
    /// Closed evidence class.
    pub evidence_kind: EvidenceKind,
    /// Opaque reference into a governed evidence store.
    pub object_reference: ObjectReference,
    /// SHA-256 digest of the externally retained evidence.
    pub evidence_digest: EvidenceDigest,
    /// Policy revision governing collection and retention.
    pub policy_version: PolicyVersion,
}

/// Immutable moderation evidence reference; it never contains raw evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModerationEvidence {
    /// Evidence identity.
    pub id: EvidenceId,
    /// Owning report.
    pub report_id: ReportId,
    /// Owning appeal when appeal-specific.
    pub appeal_id: Option<AppealId>,
    /// Closed evidence class.
    pub evidence_kind: EvidenceKind,
    /// Opaque governed-store reference.
    pub object_reference: ObjectReference,
    /// Fixed evidence digest.
    pub evidence_digest: EvidenceDigest,
    /// Governing policy revision.
    pub policy_version: PolicyVersion,
    /// Actor that collected the evidence.
    pub collected_by: ActorIdentity,
    /// Effective collection time.
    pub collected_at: OffsetDateTime,
}

/// Explicit authority under which a moderation action or appeal decision was recorded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ModerationActorRole {
    /// Human moderator.
    Moderator,
    /// Human administrator.
    Administrator,
    /// Approved system or service-account policy automation.
    Automated,
}

impl ModerationActorRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Moderator => "moderator",
            Self::Administrator => "administrator",
            Self::Automated => "automated",
        }
    }
}

/// Closed moderation action vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationActionKind {
    /// Issue a warning.
    Warning,
    /// Remove governed content.
    ContentRemoved,
    /// Apply an account restriction.
    AccountRestricted,
    /// Suspend an account.
    AccountSuspended,
    /// Dismiss the report without a subject sanction.
    ReportDismissed,
    /// Escalate to a separately authorized workflow.
    Escalated,
}

impl ModerationActionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::ContentRemoved => "content_removed",
            Self::AccountRestricted => "account_restricted",
            Self::AccountSuspended => "account_suspended",
            Self::ReportDismissed => "report_dismissed",
            Self::Escalated => "escalated",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "warning" => Some(Self::Warning),
            "content_removed" => Some(Self::ContentRemoved),
            "account_restricted" => Some(Self::AccountRestricted),
            "account_suspended" => Some(Self::AccountSuspended),
            "report_dismissed" => Some(Self::ReportDismissed),
            "escalated" => Some(Self::Escalated),
            _ => None,
        }
    }
}

/// Exact sanction duration exposed to authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModerationDuration {
    /// The action has no configured expiry.
    Permanent,
    /// The action expires at this exact server-validated instant.
    Until(OffsetDateTime),
}

/// Invalid server-owned automated moderation allowlist.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum AutomatedModerationPolicyError {
    /// An action appeared more than once.
    #[error("automated moderation allowlist contains a duplicate action")]
    DuplicateAction,
    /// The allowlist exceeded the closed action vocabulary.
    #[error("automated moderation allowlist exceeds six actions")]
    TooMany,
}

/// Server-owned allowlist for actions an automated principal may apply.
#[derive(Clone, Debug)]
pub struct AutomatedModerationPolicy {
    allowed: Arc<Vec<ModerationActionKind>>,
}

impl AutomatedModerationPolicy {
    /// Validates an explicit allowlist.
    ///
    /// Empty disables automated actions. Suspension and dismissal are denied unless explicitly
    /// included.
    ///
    /// # Errors
    ///
    /// Returns [`AutomatedModerationPolicyError`] for duplicates or oversized input.
    pub fn new(allowed: Vec<ModerationActionKind>) -> Result<Self, AutomatedModerationPolicyError> {
        if allowed.len() > 6 {
            return Err(AutomatedModerationPolicyError::TooMany);
        }
        for (index, action) in allowed.iter().enumerate() {
            if allowed[..index].contains(action) {
                return Err(AutomatedModerationPolicyError::DuplicateAction);
            }
        }
        Ok(Self {
            allowed: Arc::new(allowed),
        })
    }

    pub(crate) fn permits(&self, action: ModerationActionKind) -> bool {
        self.allowed.contains(&action)
    }
}

/// Command shared by role-specific action methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordModerationAction {
    /// Report receiving the action.
    pub report_id: ReportId,
    /// Expected tenant.
    pub tenant_id: TenantId,
    /// Expected reported subject.
    pub subject_id: SubjectId,
    /// Closed action.
    pub action_kind: ModerationActionKind,
    /// Product-local bounded reason.
    pub reason_code: ReasonCode,
    /// Exact policy revision used for the decision.
    pub policy_version: PolicyVersion,
    /// Optional action expiry; `None` means policy-defined permanence.
    pub effective_until: Option<OffsetDateTime>,
}

/// Immutable moderation action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModerationAction {
    /// Action identity.
    pub id: ModerationActionId,
    /// Owning report.
    pub report_id: ReportId,
    /// Affected subject.
    pub subject_id: SubjectId,
    /// Explicit authority class.
    pub actor_role: ModerationActorRole,
    /// Authenticated or system actor.
    pub actor: ActorIdentity,
    /// Closed action.
    pub action_kind: ModerationActionKind,
    /// Product-local reason.
    pub reason_code: ReasonCode,
    /// Governing policy revision.
    pub policy_version: PolicyVersion,
    /// Optional action expiry.
    pub effective_until: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

/// Command for the affected subject to appeal one moderation action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitAppeal {
    /// Report owning the action.
    pub report_id: ReportId,
    /// Action being appealed.
    pub action_id: ModerationActionId,
    /// Expected tenant.
    pub tenant_id: TenantId,
    /// Subject affected by the action.
    pub subject_id: SubjectId,
    /// Product-local appeal reason.
    pub reason_code: ReasonCode,
    /// Policy revision governing the appeal.
    pub policy_version: PolicyVersion,
}

/// Durable appeal state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppealState {
    /// Awaiting decision.
    Submitted,
    /// The appealed action was upheld.
    Upheld,
    /// The appeal was denied and action remains.
    Denied,
}

/// Durable moderation appeal without raw free-form content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppealRecord {
    /// Appeal identity.
    pub id: AppealId,
    /// Owning report.
    pub report_id: ReportId,
    /// Appealed action.
    pub action_id: ModerationActionId,
    /// Affected subject.
    pub subject_id: SubjectId,
    /// Product-local reason.
    pub reason_code: ReasonCode,
    /// Governing policy revision.
    pub policy_version: PolicyVersion,
    /// Durable state.
    pub state: AppealState,
    /// Optimistic state revision.
    pub version: u64,
    /// Submission time.
    pub submitted_at: OffsetDateTime,
    /// Decision time after completion.
    pub decided_at: Option<OffsetDateTime>,
}

/// Closed appeal decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealDecisionKind {
    /// Reverse or remediate the appealed action.
    Upheld,
    /// Leave the appealed action in place.
    Denied,
}

impl AppealDecisionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Upheld => "upheld",
            Self::Denied => "denied",
        }
    }
}

/// Command shared by moderator- and administrator-specific appeal methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecideAppeal {
    /// Appeal to decide.
    pub appeal_id: AppealId,
    /// Expected tenant.
    pub tenant_id: TenantId,
    /// Closed decision.
    pub decision: AppealDecisionKind,
    /// Product-local decision reason.
    pub reason_code: ReasonCode,
    /// Exact policy revision used for the decision.
    pub policy_version: PolicyVersion,
}

/// Immutable appeal decision evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppealDecision {
    /// Decision identity.
    pub id: AppealDecisionId,
    /// Decided appeal.
    pub appeal_id: AppealId,
    /// Explicit human authority.
    pub actor_role: ModerationActorRole,
    /// Authenticated human actor.
    pub actor: ActorIdentity,
    /// Closed decision.
    pub decision: AppealDecisionKind,
    /// Product-local reason.
    pub reason_code: ReasonCode,
    /// Governing policy revision.
    pub policy_version: PolicyVersion,
    /// Effective decision time.
    pub decided_at: OffsetDateTime,
}
