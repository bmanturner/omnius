use rsk_auth_core::{Principal, SubjectId, TenantId};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    ConsentDocumentKind, ConsentEvidenceFormat, ConsentSource, ConsentTransport, Jurisdiction,
    ModerationActionKind, ModerationDuration, PolicyVersion, ReasonCode,
};

/// A moderation operation with an explicit authority and purpose.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ModerationAuthorizationAction {
    /// A reporter submits a report.
    ReporterSubmitReport,
    /// A reporter attaches an evidence reference to their report.
    ReporterAddEvidence,
    /// A reporter reads their own report.
    ReporterViewOwnReport,
    /// A reported subject reads a report affecting them.
    SubjectViewReport,
    /// A reported subject appeals an action affecting them.
    SubjectSubmitAppeal,
    /// A subject attaches evidence to their appeal.
    SubjectAddAppealEvidence,
    /// A moderator reads a report.
    ModeratorViewReport,
    /// A moderator begins reviewing a report.
    ModeratorBeginReview,
    /// A moderator attaches reviewed evidence.
    ModeratorAddEvidence,
    /// A moderator records a moderation action.
    ModeratorRecordAction,
    /// A moderator decides an appeal when policy permits.
    ModeratorDecideAppeal,
    /// An administrator reads a report.
    AdministratorViewReport,
    /// An administrator attaches reviewed evidence.
    AdministratorAddEvidence,
    /// An administrator records a moderation action.
    AdministratorRecordAction,
    /// An administrator decides an appeal.
    AdministratorDecideAppeal,
    /// An approved automated service attaches a provider attestation.
    AutomatedAddEvidence,
    /// An approved automated service records a policy action.
    AutomatedRecordAction,
}

/// Every privacy application action passed to the injected authorizer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrivacyAuthorizationAction {
    /// A subject requests lifecycle work for their own data.
    LifecycleRequestOwnSubject,
    /// An administrator requests tenant-wide or another subject's lifecycle work.
    LifecycleRequestTenant,
    /// A subject reads their own lifecycle request status.
    LifecycleViewOwnSubject,
    /// An administrator reads tenant lifecycle status.
    LifecycleViewTenant,
    /// An administrator reviews a dead-lettered lifecycle request.
    LifecycleDeadLetterReview,
    /// An administrator redrives a dead-lettered lifecycle request.
    LifecycleDeadLetterRedrive,
    /// A subject reads their own completed export manifest.
    ExportManifestViewOwnSubject,
    /// An administrator reads a completed tenant export manifest.
    ExportManifestViewTenant,
    /// A legal hold is placed.
    LegalHoldPlace,
    /// A legal hold is released.
    LegalHoldRelease,
    /// An authorized actor reads legal-hold status.
    LegalHoldView,
    /// A subject records their own consent evidence.
    ConsentRecordSelf,
    /// An administrator records consent evidence for another subject.
    ConsentRecordAdministrative,
    /// A subject withdraws their own consent.
    ConsentWithdrawSelf,
    /// An administrator withdraws another subject's consent.
    ConsentWithdrawAdministrative,
    /// An authority-specific moderation operation.
    Moderation(ModerationAuthorizationAction),
}

/// Server-derived consent facts supplied to authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentAuthorizationContext {
    /// Governed document kind.
    pub document_kind: ConsentDocumentKind,
    /// Exact governed document version.
    pub document_version: PolicyVersion,
    /// Applicable jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// Trusted application transport used for policy selection.
    pub transport: ConsentTransport,
    /// Trusted policy-derived collection source.
    pub source: ConsentSource,
    /// Trusted policy-derived evidence ceremony.
    pub evidence_format: ConsentEvidenceFormat,
    /// Server-derived effective instant for this evidence operation.
    pub effective_at: OffsetDateTime,
    /// Trusted policy-derived withdrawal capability.
    pub withdrawal_permitted: bool,
    /// Immutable original grant source when authorizing a withdrawal.
    pub grant_source: Option<ConsentSource>,
    /// Immutable original grant evidence ceremony when authorizing a withdrawal.
    pub grant_evidence_format: Option<ConsentEvidenceFormat>,
}

/// Exact moderation decision facts supplied to authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModerationAuthorizationContext {
    /// Closed action, when an action is being decided.
    pub action_kind: Option<ModerationActionKind>,
    /// Exact policy revision.
    pub policy_version: PolicyVersion,
    /// Bounded product-local reason class.
    pub reason_code: ReasonCode,
    /// Exact server-validated sanction duration, when applicable.
    pub duration: Option<ModerationDuration>,
}

/// Stable resource and policy facts supplied to authorization without transport payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyResource {
    /// Tenant containing the protected record.
    pub tenant_id: TenantId,
    /// Subject affected by the action, when one exists.
    pub subject_id: Option<SubjectId>,
    /// Original reporter, when authorizing report ownership.
    pub reporter_subject_id: Option<SubjectId>,
    /// Server-derived consent facts, when authorizing consent evidence.
    pub consent: Option<ConsentAuthorizationContext>,
    /// Exact moderation facts, when authorizing moderation work.
    pub moderation: Option<ModerationAuthorizationContext>,
}

impl PrivacyResource {
    /// Creates tenant-scoped resource facts.
    #[must_use]
    pub const fn tenant(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            subject_id: None,
            reporter_subject_id: None,
            consent: None,
            moderation: None,
        }
    }

    /// Creates subject-scoped resource facts.
    #[must_use]
    pub const fn subject(tenant_id: TenantId, subject_id: SubjectId) -> Self {
        Self {
            tenant_id,
            subject_id: Some(subject_id),
            reporter_subject_id: None,
            consent: None,
            moderation: None,
        }
    }

    /// Adds the report owner used for reporter-specific decisions.
    #[must_use]
    pub const fn reported_by(mut self, reporter_subject_id: SubjectId) -> Self {
        self.reporter_subject_id = Some(reporter_subject_id);
        self
    }

    /// Adds trusted policy-derived consent facts.
    #[must_use]
    pub fn with_consent(mut self, context: ConsentAuthorizationContext) -> Self {
        self.consent = Some(context);
        self
    }

    /// Adds exact moderation policy facts.
    #[must_use]
    pub fn with_moderation(mut self, context: ModerationAuthorizationContext) -> Self {
        self.moderation = Some(context);
        self
    }
}

/// Authorization denied without retaining policy or subject details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("privacy action is not authorized")]
pub struct AuthorizationDenied;

/// Application-service authorization boundary shared by every transport.
///
/// Implementations may call the built-in or Cedar authorization provider. Feature flags must never
/// implement this decision. Errors and implementations must not log evidence or request payloads.
pub trait PrivacyAuthorizer: Send + Sync {
    /// Authorizes one explicit action against stable resource facts.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationDenied`] when the action is not permitted.
    fn authorize(
        &self,
        principal: &Principal,
        action: PrivacyAuthorizationAction,
        resource: PrivacyResource,
    ) -> Result<(), AuthorizationDenied>;
}
