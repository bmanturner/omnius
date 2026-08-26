use std::sync::Arc;

use rsk_auth_core::{Principal, PrincipalKind, SubjectId, TenantId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ActorIdentity, EvidenceDigest, Jurisdiction, PolicyVersion, types::privacy_uuid_id};

privacy_uuid_id!(ConsentId, "An immutable consent evidence identity.");
privacy_uuid_id!(
    ConsentWithdrawalId,
    "An immutable consent withdrawal identity."
);

/// Closed class of versioned legal or consent document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDocumentKind {
    /// Acceptance of terms of service.
    Terms,
    /// Acknowledgement of a privacy policy revision.
    PrivacyPolicy,
    /// Optional direct-marketing consent.
    Marketing,
    /// Data-processing consent where consent is the governing basis.
    DataProcessing,
    /// Optional cookie or similar-device-storage consent.
    Cookies,
}

impl ConsentDocumentKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Terms => "terms",
            Self::PrivacyPolicy => "privacy_policy",
            Self::Marketing => "marketing",
            Self::DataProcessing => "data_processing",
            Self::Cookies => "cookies",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "terms" => Some(Self::Terms),
            "privacy_policy" => Some(Self::PrivacyPolicy),
            "marketing" => Some(Self::Marketing),
            "data_processing" => Some(Self::DataProcessing),
            "cookies" => Some(Self::Cookies),
            _ => None,
        }
    }
}

/// Closed channel through which consent evidence was collected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSource {
    /// Browser application.
    Web,
    /// Native mobile application.
    Mobile,
    /// Authenticated API operation.
    Api,
    /// Reviewed legacy-system import.
    Import,
    /// Authorized support workflow.
    Support,
    /// Non-interactive policy record.
    SystemPolicy,
}

impl ConsentSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Mobile => "mobile",
            Self::Api => "api",
            Self::Import => "import",
            Self::Support => "support",
            Self::SystemPolicy => "system_policy",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "web" => Some(Self::Web),
            "mobile" => Some(Self::Mobile),
            "api" => Some(Self::Api),
            "import" => Some(Self::Import),
            "support" => Some(Self::Support),
            "system_policy" => Some(Self::SystemPolicy),
            _ => None,
        }
    }
}

/// Closed representation of the hashed evidence ceremony.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentEvidenceFormat {
    /// Explicit checkbox or equivalent affirmative control.
    Checkbox,
    /// Electronic signature ceremony.
    ElectronicSignature,
    /// Reviewed attestation imported from another system.
    ImportedAttestation,
    /// System-authored policy evidence without a human interaction.
    PolicyRecord,
}

impl ConsentEvidenceFormat {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Checkbox => "checkbox",
            Self::ElectronicSignature => "electronic_signature",
            Self::ImportedAttestation => "imported_attestation",
            Self::PolicyRecord => "policy_record",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "checkbox" => Some(Self::Checkbox),
            "electronic_signature" => Some(Self::ElectronicSignature),
            "imported_attestation" => Some(Self::ImportedAttestation),
            "policy_record" => Some(Self::PolicyRecord),
            _ => None,
        }
    }
}
/// Trusted application transport used to select a server-owned consent rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentTransport {
    /// First-party browser application.
    Web,
    /// First-party native application.
    Mobile,
    /// Authenticated public API.
    Api,
    /// Reviewed administrative import.
    AdministrativeImport,
    /// Authorized support tooling.
    Support,
    /// Internal policy automation.
    System,
}

/// One trusted consent grant ceremony selected by document, jurisdiction, actor, and transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentRule {
    /// Document class governed by this rule.
    pub document_kind: ConsentDocumentKind,
    /// Exact governed document version.
    pub document_version: PolicyVersion,
    /// Applicable jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// Actor class allowed to use the rule.
    pub actor_kind: PrincipalKind,
    /// Trusted application transport.
    pub transport: ConsentTransport,
    /// Persisted evidence source derived by policy.
    pub source: ConsentSource,
    /// Persisted evidence ceremony derived by policy.
    pub evidence_format: ConsentEvidenceFormat,
    /// Whether this immutable grant may later be withdrawn.
    pub withdrawal_permitted: bool,
}

/// Current trusted withdrawal ceremony independent of historical grant document versions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentWithdrawalRule {
    /// Applicable withdrawal jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// Actor class allowed to use the rule.
    pub actor_kind: PrincipalKind,
    /// Trusted application transport.
    pub transport: ConsentTransport,
    /// Persisted withdrawal source derived by policy.
    pub source: ConsentSource,
    /// Persisted withdrawal evidence ceremony derived by policy.
    pub evidence_format: ConsentEvidenceFormat,
}

/// Invalid server-owned consent policy configuration or lookup.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ConsentPolicyError {
    /// No configured grant or withdrawal rule matched the trusted command facts.
    #[error("no consent policy rule matches the command")]
    NoMatchingRule,
    /// The policy contains two rules for the same operation-specific key.
    #[error("consent policy contains a duplicate rule")]
    DuplicateRule,
    /// The policy contains no grant rules.
    #[error("consent grant policy must not be empty")]
    Empty,
    /// A withdrawable grant has no withdrawal ceremony for the same actor and transport.
    #[error("withdrawable consent grant lacks a matching withdrawal rule")]
    MissingWithdrawalRule,
    /// The combined policy exceeded its public bound.
    #[error("consent policy exceeds 128 rules")]
    TooMany,
}

/// Bounded server-owned grant and withdrawal rules injected into the application service.
#[derive(Clone, Debug)]
pub struct ConsentPolicy {
    grant_rules: Arc<Vec<ConsentRule>>,
    withdrawal_rules: Arc<Vec<ConsentWithdrawalRule>>,
}

impl ConsentPolicy {
    /// Validates and owns trusted grant and current withdrawal rules.
    ///
    /// # Errors
    ///
    /// Returns [`ConsentPolicyError`] for empty grants, oversized input, duplicate keys, or a
    /// withdrawable grant without a matching withdrawal ceremony.
    pub fn new(
        grant_rules: Vec<ConsentRule>,
        withdrawal_rules: Vec<ConsentWithdrawalRule>,
    ) -> Result<Self, ConsentPolicyError> {
        if grant_rules.is_empty() {
            return Err(ConsentPolicyError::Empty);
        }
        if grant_rules.len().saturating_add(withdrawal_rules.len()) > 128 {
            return Err(ConsentPolicyError::TooMany);
        }
        for (index, rule) in grant_rules.iter().enumerate() {
            if grant_rules[..index].iter().any(|existing| {
                existing.document_kind == rule.document_kind
                    && existing.document_version == rule.document_version
                    && existing.jurisdiction == rule.jurisdiction
                    && existing.actor_kind == rule.actor_kind
                    && existing.transport == rule.transport
            }) {
                return Err(ConsentPolicyError::DuplicateRule);
            }
        }
        for (index, rule) in withdrawal_rules.iter().enumerate() {
            if withdrawal_rules[..index].iter().any(|existing| {
                existing.jurisdiction == rule.jurisdiction
                    && existing.actor_kind == rule.actor_kind
                    && existing.transport == rule.transport
            }) {
                return Err(ConsentPolicyError::DuplicateRule);
            }
        }
        if grant_rules.iter().any(|grant| {
            grant.withdrawal_permitted
                && !withdrawal_rules.iter().any(|withdrawal| {
                    withdrawal.jurisdiction == grant.jurisdiction
                        && withdrawal.actor_kind == grant.actor_kind
                        && withdrawal.transport == grant.transport
                })
        }) {
            return Err(ConsentPolicyError::MissingWithdrawalRule);
        }
        Ok(Self {
            grant_rules: Arc::new(grant_rules),
            withdrawal_rules: Arc::new(withdrawal_rules),
        })
    }

    pub(crate) fn resolve_grant(
        &self,
        principal: &Principal,
        transport: ConsentTransport,
        document_kind: ConsentDocumentKind,
        document_version: &PolicyVersion,
        jurisdiction: &Jurisdiction,
    ) -> Result<&ConsentRule, ConsentPolicyError> {
        self.grant_rules
            .iter()
            .find(|rule| {
                rule.document_kind == document_kind
                    && &rule.document_version == document_version
                    && &rule.jurisdiction == jurisdiction
                    && rule.actor_kind == principal.kind
                    && rule.transport == transport
            })
            .ok_or(ConsentPolicyError::NoMatchingRule)
    }

    pub(crate) fn resolve_withdrawal(
        &self,
        principal: &Principal,
        transport: ConsentTransport,
        jurisdiction: &Jurisdiction,
    ) -> Result<&ConsentWithdrawalRule, ConsentPolicyError> {
        self.withdrawal_rules
            .iter()
            .find(|rule| {
                &rule.jurisdiction == jurisdiction
                    && rule.actor_kind == principal.kind
                    && rule.transport == transport
            })
            .ok_or(ConsentPolicyError::NoMatchingRule)
    }
}

/// Command to append immutable evidence of one document version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordConsent {
    /// Tenant containing the subject.
    pub tenant_id: TenantId,
    /// Subject whose evidence is recorded.
    pub subject_id: SubjectId,
    /// Closed document class.
    pub document_kind: ConsentDocumentKind,
    /// Exact externally governed document revision.
    pub document_version: PolicyVersion,
    /// Applicable jurisdiction at collection time.
    pub jurisdiction: Jurisdiction,
    /// SHA-256 digest of transient evidence; no raw evidence is persisted.
    pub evidence_digest: EvidenceDigest,
}

/// Immutable stored consent evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentRecord {
    /// Evidence identity.
    pub id: ConsentId,
    /// Tenant containing the subject.
    pub tenant_id: TenantId,
    /// Subject who consented.
    pub subject_id: SubjectId,
    /// Closed document class.
    pub document_kind: ConsentDocumentKind,
    /// Exact document revision.
    pub document_version: PolicyVersion,
    /// Applicable jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// Collection channel.
    pub source: ConsentSource,
    /// Evidence ceremony class.
    pub evidence_format: ConsentEvidenceFormat,
    /// Fixed evidence digest.
    pub evidence_digest: EvidenceDigest,
    /// Whether withdrawal is permitted.
    pub withdrawal_permitted: bool,
    /// Acceptance instant.
    pub accepted_at: OffsetDateTime,
    /// Authenticated or system actor that recorded the evidence.
    pub recorded_by: ActorIdentity,
    /// Durable insertion time.
    pub created_at: OffsetDateTime,
}

/// Command to append a withdrawal for an existing withdrawable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawConsent {
    /// Consent evidence being withdrawn.
    pub consent_id: ConsentId,
    /// Expected tenant, preventing cross-tenant identifier use.
    pub tenant_id: TenantId,
    /// Expected subject, preventing another subject's withdrawal.
    pub subject_id: SubjectId,
    /// Jurisdiction applicable at withdrawal time.
    pub jurisdiction: Jurisdiction,
    /// SHA-256 digest of transient withdrawal evidence.
    pub evidence_digest: EvidenceDigest,
}

/// Immutable withdrawal evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentWithdrawal {
    /// Withdrawal identity.
    pub id: ConsentWithdrawalId,
    /// Withdrawn consent identity.
    pub consent_id: ConsentId,
    /// Applicable jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// Withdrawal channel.
    pub source: ConsentSource,
    /// Evidence ceremony class.
    pub evidence_format: ConsentEvidenceFormat,
    /// Fixed evidence digest.
    pub evidence_digest: EvidenceDigest,
    /// Effective withdrawal instant.
    pub withdrawn_at: OffsetDateTime,
    /// Authenticated or system actor that recorded the withdrawal.
    pub recorded_by: ActorIdentity,
    /// Durable insertion time.
    pub created_at: OffsetDateTime,
}
