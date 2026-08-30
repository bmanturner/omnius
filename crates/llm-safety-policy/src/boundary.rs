use std::fmt;

use omnius_agent_capability_registry::{
    CapabilityKey, CapabilityRegistry, ConfirmationEvidence, ConfirmationPolicy, Exposure,
    SideEffect,
};
use omnius_llm_prompt_catalog::{
    AssembledContext, ContentDigest, ContextProvenance, ContextRecord, ContextSourceKind,
    RenderedPrompt,
};
use omnius_outbound_http::ApprovedUrl;
use thiserror::Error;

use crate::SafetyReasonCode;

/// Fixed digest linking a boundary decision to provenance without retaining content.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProvenanceDigest([u8; 32]);

impl ProvenanceDigest {
    /// Creates a nonempty provenance digest.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError`] for an all-zero digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, ProvenanceError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(ProvenanceError)
    }

    /// Returns the fixed digest bytes for context-manifest correlation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProvenanceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvenanceDigest([redacted digest])")
    }
}

/// A provenance digest was empty.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("content provenance evidence is invalid")]
pub struct ProvenanceError;

/// Application-controlled privileged instruction sources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionSource {
    /// Immutable system policy or a published system prompt revision.
    SystemPolicy,
    /// Immutable application developer policy or a published developer prompt revision.
    DeveloperPolicy,
}

/// Sources that are always data, never privileged instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UntrustedSource {
    /// End-user supplied message content.
    UserMessage,
    /// Retrieved document content.
    RetrievedDocument,
    /// Tool result content.
    ToolOutput,
    /// Prior or nested model output.
    ModelOutput,
    /// Retrieved web content.
    WebContent,
    /// Uploaded or application-owned file content.
    FileContent,
}

/// Provenance-bearing instruction or untrusted-data label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentProvenance {
    kind: ContentProvenanceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentProvenanceKind {
    PrivilegedInstruction {
        source: InstructionSource,
        revision_digest: ProvenanceDigest,
    },
    UntrustedData {
        source: UntrustedSource,
        source_digest: ProvenanceDigest,
    },
}

impl ContentProvenance {
    /// Derives privileged provenance from an actually rendered immutable prompt channel.
    #[must_use]
    pub fn from_rendered_prompt(
        prompt: &RenderedPrompt,
        source: InstructionSource,
    ) -> Option<Self> {
        let instruction = match source {
            InstructionSource::SystemPolicy => prompt.system(),
            InstructionSource::DeveloperPolicy => prompt.developer(),
        }?;
        Some(Self {
            kind: ContentProvenanceKind::PrivilegedInstruction {
                source,
                revision_digest: ProvenanceDigest(
                    *ContentDigest::of(instruction.as_str().as_bytes()).as_bytes(),
                ),
            },
        })
    }

    /// Labels external, user, tool, file, or model content as untrusted data.
    #[must_use]
    pub const fn untrusted(source: UntrustedSource, source_digest: ProvenanceDigest) -> Self {
        Self {
            kind: ContentProvenanceKind::UntrustedData {
                source,
                source_digest,
            },
        }
    }

    /// Adapts an authorized context-assembler provenance record without changing its trust.
    #[must_use]
    pub fn from_context_provenance(provenance: &ContextProvenance) -> Self {
        let source = match provenance.source_kind() {
            ContextSourceKind::Document => UntrustedSource::RetrievedDocument,
            ContextSourceKind::Web => UntrustedSource::WebContent,
            ContextSourceKind::ToolOutput => UntrustedSource::ToolOutput,
            ContextSourceKind::ModelOutput => UntrustedSource::ModelOutput,
        };
        Self::untrusted(
            source,
            ProvenanceDigest(*provenance.content_digest().as_bytes()),
        )
    }

    /// Reports whether the provenance is an application-controlled instruction revision.
    #[must_use]
    pub const fn is_privileged_instruction(self) -> bool {
        matches!(
            self.kind,
            ContentProvenanceKind::PrivilegedInstruction { .. }
        )
    }
}

/// Requested context placement for provenance-bearing content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentPlacement {
    /// System or developer instruction channel.
    PrivilegedInstruction,
    /// Delimited data channel.
    Data,
}

/// Fail-closed result of instruction/data boundary evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryDecision {
    /// The safety policy imposes no additional restriction on this placement.
    ///
    /// This is not an authorization decision.
    NoAdditionalRestriction,
    /// The requested placement violates the instruction/data boundary.
    Restricted(SafetyReasonCode),
}

impl BoundaryDecision {
    /// Evaluates a placement while verifying privileged provenance against the placed bytes.
    #[must_use]
    pub fn evaluate(
        provenance: ContentProvenance,
        placement: ContentPlacement,
        placed_content: &[u8],
    ) -> Self {
        match (provenance.kind, placement) {
            (
                ContentProvenanceKind::PrivilegedInstruction {
                    revision_digest, ..
                },
                ContentPlacement::PrivilegedInstruction,
            ) if revision_digest
                == ProvenanceDigest(*ContentDigest::of(placed_content).as_bytes()) =>
            {
                Self::NoAdditionalRestriction
            }
            (
                ContentProvenanceKind::PrivilegedInstruction { .. }
                | ContentProvenanceKind::UntrustedData { .. },
                ContentPlacement::PrivilegedInstruction,
            ) => Self::Restricted(SafetyReasonCode::UntrustedContentCannotBeInstruction),
            (
                ContentProvenanceKind::PrivilegedInstruction { .. }
                | ContentProvenanceKind::UntrustedData { .. },
                ContentPlacement::Data,
            ) => Self::NoAdditionalRestriction,
        }
    }

    /// Evaluates a context-assembler record using its unchanged provenance label.
    #[must_use]
    pub fn evaluate_context_record(record: &ContextRecord, placement: ContentPlacement) -> Self {
        Self::evaluate(
            ContentProvenance::from_context_provenance(record.provenance()),
            placement,
            record.content().as_str().as_bytes(),
        )
    }

    /// Evaluates the context assembler's fixed untrusted-data channel as a whole.
    #[must_use]
    pub const fn evaluate_assembled_context(
        _context: &AssembledContext,
        placement: ContentPlacement,
    ) -> Self {
        match placement {
            ContentPlacement::PrivilegedInstruction => {
                Self::Restricted(SafetyReasonCode::UntrustedContentCannotBeInstruction)
            }
            ContentPlacement::Data => Self::NoAdditionalRestriction,
        }
    }
}

/// Opaque content-bound prompt-injection assessment from the built-in detector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InjectionIndicator {
    outcome: InjectionOutcome,
    content_digest: ProvenanceDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectionOutcome {
    NoneObserved,
    Suspicious,
    LikelyInjection,
}

impl InjectionIndicator {
    /// Assesses untrusted bytes without retaining their content.
    #[must_use]
    pub fn assess(content: &[u8]) -> Self {
        let likely = contains_ascii_case_insensitive(content, b"ignore previous")
            || contains_ascii_case_insensitive(content, b"override system");
        let suspicious = contains_ascii_case_insensitive(content, b"system prompt")
            || contains_ascii_case_insensitive(content, b"developer message");
        let outcome = if likely {
            InjectionOutcome::LikelyInjection
        } else if suspicious {
            InjectionOutcome::Suspicious
        } else {
            InjectionOutcome::NoneObserved
        };
        Self {
            outcome,
            content_digest: ProvenanceDigest(*ContentDigest::of(content).as_bytes()),
        }
    }

    /// Returns the content digest bound to this assessment.
    #[must_use]
    pub const fn content_digest(self) -> ProvenanceDigest {
        self.content_digest
    }
}

/// Evidence that a tool target is live and LLM-exposed in the canonical registry.
#[derive(Clone, Copy)]
pub struct ToolAuthority<'a> {
    capability: &'a CapabilityKey,
    side_effect: SideEffect,
    confirmation_policy: ConfirmationPolicy,
}

impl<'a> ToolAuthority<'a> {
    /// Resolves a live LLM-tool capability through the canonical registry.
    ///
    /// # Errors
    ///
    /// Returns [`ToolAuthorityError`] when the capability is absent, unavailable,
    /// or does not declare the LLM-tool exposure.
    pub fn from_registry(
        registry: &CapabilityRegistry,
        capability: &'a CapabilityKey,
    ) -> Result<Self, ToolAuthorityError> {
        let availability = registry.availability(capability);
        if !availability.compiled() || !availability.runtime().is_available() {
            return Err(ToolAuthorityError::Unavailable);
        }
        let Some(document) = registry.document(capability) else {
            return Err(ToolAuthorityError::Unavailable);
        };
        if document
            .exposures
            .binary_search(&Exposure::LlmTool)
            .is_err()
        {
            return Err(ToolAuthorityError::LlmToolExposureNotDeclared);
        }
        Ok(Self {
            capability,
            side_effect: document.side_effect,
            confirmation_policy: document.confirmation,
        })
    }

    /// Borrows the registry-resolved capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        self.capability
    }

    /// Returns the registry-owned side-effect class.
    #[must_use]
    pub const fn side_effect(&self) -> SideEffect {
        self.side_effect
    }

    /// Returns the registry-owned confirmation policy.
    #[must_use]
    pub const fn confirmation_policy(&self) -> ConfirmationPolicy {
        self.confirmation_policy
    }
}

impl fmt::Debug for ToolAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolAuthority([registry resolved])")
    }
}

/// Closed canonical registry resolution failures for proposed LLM tool calls.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolAuthorityError {
    /// The capability is absent or not currently available.
    #[error("LLM tool capability is unavailable")]
    Unavailable,
    /// The capability does not declare the canonical LLM-tool exposure.
    #[error("capability does not declare LLM tool exposure")]
    LlmToolExposureNotDeclared,
}

/// Central outbound-HTTP destination admission for proposed model egress.
#[derive(Clone, Copy)]
pub enum EgressAuthority<'a> {
    /// No server egress decision accompanied the request.
    Missing,
    /// Server policy denied the destination or operation.
    DeniedByServerPolicy,
    /// The exact destination passed the centralized outbound URL policy.
    Approved(&'a ApprovedUrl),
}

impl EgressAuthority<'_> {
    /// Borrows the exact centrally approved destination, when present.
    #[must_use]
    pub const fn approved_url(&self) -> Option<&ApprovedUrl> {
        match self {
            Self::Approved(url) => Some(url),
            Self::Missing | Self::DeniedByServerPolicy => None,
        }
    }
}

impl fmt::Debug for EgressAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self {
            Self::Missing => "missing",
            Self::DeniedByServerPolicy => "denied",
            Self::Approved(_) => "approved",
        };
        formatter
            .debug_tuple("EgressAuthority")
            .field(&state)
            .finish()
    }
}

/// One additional safety restriction, deliberately distinct from authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Restriction {
    /// This safety layer adds no restriction; authoritative authorization still applies.
    NoAdditionalRestriction,
    /// This safety layer requires the action to stop for a closed reason.
    Restricted(SafetyReasonCode),
}

/// Inputs used to restrict tool, egress, and side-effect execution.
///
/// Authorization is intentionally absent: heuristic injection evidence cannot grant or
/// deny authority, and callers must still execute tools exclusively through the registry.
pub struct ExecutionSafetyContext<'a> {
    injection: InjectionIndicator,
    tool_authority: Option<ToolAuthority<'a>>,
    egress_authority: EgressAuthority<'a>,
    confirmation_evidence: ConfirmationEvidence,
}

impl<'a> ExecutionSafetyContext<'a> {
    /// Creates a safety context from authoritative registry and server-policy facts.
    #[must_use]
    pub fn new(
        untrusted_content: &[u8],
        tool_authority: Option<ToolAuthority<'a>>,
        egress_authority: EgressAuthority<'a>,
        confirmation_evidence: ConfirmationEvidence,
    ) -> Self {
        Self {
            injection: InjectionIndicator::assess(untrusted_content),
            tool_authority,
            egress_authority,
            confirmation_evidence,
        }
    }

    /// Computes additional restrictions for the exact bytes bound at construction; it never
    /// returns an authorization decision. A content mismatch fails closed.
    #[must_use]
    pub fn restrictions(&self, untrusted_content: &[u8]) -> ExecutionRestrictions {
        let injection_restriction = injection_restriction(self.injection, untrusted_content);
        let confirmation = self.tool_authority.as_ref().map_or(
            Restriction::Restricted(SafetyReasonCode::ToolAuthorityMissing),
            |authority| {
                confirmation_restriction(
                    authority.side_effect(),
                    authority.confirmation_policy(),
                    self.confirmation_evidence,
                )
            },
        );

        let tool = injection_restriction.unwrap_or_else(|| {
            if self.tool_authority.is_none() {
                Restriction::Restricted(SafetyReasonCode::ToolAuthorityMissing)
            } else if let Restriction::Restricted(reason) = confirmation {
                Restriction::Restricted(reason)
            } else {
                Restriction::NoAdditionalRestriction
            }
        });
        let egress = injection_restriction.unwrap_or(match self.egress_authority {
            EgressAuthority::Missing => {
                Restriction::Restricted(SafetyReasonCode::EgressAuthorityMissing)
            }
            EgressAuthority::DeniedByServerPolicy => {
                Restriction::Restricted(SafetyReasonCode::EgressDeniedByServerPolicy)
            }
            EgressAuthority::Approved(_) => Restriction::NoAdditionalRestriction,
        });

        ExecutionRestrictions {
            tool,
            egress,
            confirmation,
        }
    }
}

impl fmt::Debug for ExecutionSafetyContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionSafetyContext")
            .field("injection", &self.injection)
            .field("tool_authority", &self.tool_authority)
            .field("egress_authority", &self.egress_authority)
            .field("confirmation_evidence", &self.confirmation_evidence)
            .finish()
    }
}

fn injection_restriction(
    indicator: InjectionIndicator,
    untrusted_content: &[u8],
) -> Option<Restriction> {
    if indicator.content_digest
        != ProvenanceDigest(*ContentDigest::of(untrusted_content).as_bytes())
    {
        return Some(Restriction::Restricted(
            SafetyReasonCode::InjectionIndicatorRestricted,
        ));
    }
    match indicator.outcome {
        InjectionOutcome::Suspicious | InjectionOutcome::LikelyInjection => Some(
            Restriction::Restricted(SafetyReasonCode::InjectionIndicatorRestricted),
        ),
        InjectionOutcome::NoneObserved => None,
    }
}

fn contains_ascii_case_insensitive(content: &[u8], needle: &[u8]) -> bool {
    content
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn confirmation_restriction(
    side_effect: SideEffect,
    policy: ConfirmationPolicy,
    evidence: ConfirmationEvidence,
) -> Restriction {
    if !side_effect_policy_agrees(side_effect, policy) {
        return Restriction::Restricted(SafetyReasonCode::ToolPolicyAmbiguous);
    }
    let satisfied = match policy {
        ConfirmationPolicy::Never => true,
        ConfirmationPolicy::Policy => matches!(
            evidence,
            ConfirmationEvidence::Confirmed | ConfirmationEvidence::NotRequiredByPolicy
        ),
        ConfirmationPolicy::Always => evidence == ConfirmationEvidence::Confirmed,
    };
    if satisfied {
        Restriction::NoAdditionalRestriction
    } else {
        Restriction::Restricted(SafetyReasonCode::SideEffectConfirmationRequired)
    }
}

const fn side_effect_policy_agrees(
    side_effect: SideEffect,
    confirmation: ConfirmationPolicy,
) -> bool {
    match side_effect {
        SideEffect::None => matches!(confirmation, ConfirmationPolicy::Never),
        SideEffect::Idempotent => true,
        SideEffect::Mutating | SideEffect::External => {
            !matches!(confirmation, ConfirmationPolicy::Never)
        }
        SideEffect::Destructive => matches!(confirmation, ConfirmationPolicy::Always),
    }
}

/// Additional restrictions for each execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionRestrictions {
    tool: Restriction,
    egress: Restriction,
    confirmation: Restriction,
}

impl ExecutionRestrictions {
    /// Returns the tool-execution restriction.
    #[must_use]
    pub const fn tool(self) -> Restriction {
        self.tool
    }

    /// Returns the network-egress restriction.
    #[must_use]
    pub const fn egress(self) -> Restriction {
        self.egress
    }

    /// Returns the side-effect confirmation restriction.
    #[must_use]
    pub const fn confirmation(self) -> Restriction {
        self.confirmation
    }
}
