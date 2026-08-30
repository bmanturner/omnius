use std::{cmp::Reverse, collections::BTreeSet, fmt};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AuthorizationId, ContentDigest, DataClassification, PolicyRevisionId, PrincipalId, SourceId,
    SourceRevisionId, TenantId, UntrustedText,
};

const MAX_CONTEXT_RECORDS: usize = 256;
const MAX_RETRIEVED_RECORDS: usize = 1_024;
const MAX_RETRIEVED_BYTES: usize = 4_194_304;
const MAX_CONTEXT_BYTES: usize = 1_048_576;
const MAX_CONTEXT_TOKENS: usize = 262_144;
const TOKEN_BYTES: usize = 4;

/// Identity and policy facts that retrieval authorization must bind.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextIdentity {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    policy_revision: PolicyRevisionId,
    maximum_classification: DataClassification,
}

impl ContextIdentity {
    /// Creates a tenant-, principal-, policy-, and classification-bound identity.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        policy_revision: PolicyRevisionId,
        maximum_classification: DataClassification,
    ) -> Self {
        Self {
            tenant_id,
            principal_id,
            policy_revision,
            maximum_classification,
        }
    }

    /// Borrows the tenant identifier.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Borrows the principal identifier.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Borrows the exact policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevisionId {
        &self.policy_revision
    }

    /// Returns the maximum admitted classification.
    #[must_use]
    pub const fn maximum_classification(&self) -> DataClassification {
        self.maximum_classification
    }
}

impl fmt::Debug for ContextIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextIdentity")
            .field("tenant_id", &"[REDACTED]")
            .field("principal_id", &"[REDACTED]")
            .field("policy_revision", &"[REDACTED]")
            .field("maximum_classification", &self.maximum_classification)
            .finish()
    }
}

/// Explicit deterministic whole-record context limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the four independent limits are clearer with explicit max prefixes"
)]
pub struct ContextBudget {
    max_records: usize,
    max_record_bytes: usize,
    max_total_bytes: usize,
    max_estimated_tokens: usize,
}

impl ContextBudget {
    /// Creates context limits under hard process ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidBudget`] for zero or above-ceiling values.
    pub fn new(
        max_records: usize,
        max_record_bytes: usize,
        max_total_bytes: usize,
        max_estimated_tokens: usize,
    ) -> Result<Self, ContextError> {
        if max_records == 0
            || max_records > MAX_CONTEXT_RECORDS
            || max_record_bytes == 0
            || max_record_bytes > MAX_CONTEXT_BYTES
            || max_total_bytes == 0
            || max_total_bytes > MAX_CONTEXT_BYTES
            || max_estimated_tokens == 0
            || max_estimated_tokens > MAX_CONTEXT_TOKENS
        {
            return Err(ContextError::InvalidBudget);
        }
        Ok(Self {
            max_records,
            max_record_bytes,
            max_total_bytes,
            max_estimated_tokens,
        })
    }
}

/// An authorization request that contains no retrieval result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextAuthorizationRequest {
    identity: ContextIdentity,
    query: UntrustedText,
    deadline_epoch_ms: u64,
}

impl ContextAuthorizationRequest {
    /// Creates an authorization request with an explicit caller deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidDeadline`] when the deadline is zero.
    pub fn new(
        identity: ContextIdentity,
        query: UntrustedText,
        deadline_epoch_ms: u64,
    ) -> Result<Self, ContextError> {
        if deadline_epoch_ms == 0 {
            return Err(ContextError::InvalidDeadline);
        }
        Ok(Self {
            identity,
            query,
            deadline_epoch_ms,
        })
    }

    /// Borrows tenant, principal, policy, and classification facts.
    #[must_use]
    pub const fn identity(&self) -> &ContextIdentity {
        &self.identity
    }

    /// Borrows the untrusted retrieval query.
    #[must_use]
    pub const fn query(&self) -> &UntrustedText {
        &self.query
    }

    /// Returns the absolute caller deadline in Unix milliseconds.
    #[must_use]
    pub const fn deadline_epoch_ms(&self) -> u64 {
        self.deadline_epoch_ms
    }
}

/// A value-free authorization result used before any retrieval call.
#[derive(Clone, Eq, PartialEq)]
pub enum ContextAuthorizationDecision {
    /// Retrieval is denied.
    Denied,
    /// Retrieval is allowed under exact authorization and grant revisions.
    Allowed {
        /// Stable authorization-decision identifier.
        authorization_id: AuthorizationId,
        /// Exact grant revision included in scope and cache isolation.
        grant_revision: PolicyRevisionId,
    },
}

impl fmt::Debug for ContextAuthorizationDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied => formatter.write_str("ContextAuthorizationDecision::Denied"),
            Self::Allowed { .. } => {
                formatter.write_str("ContextAuthorizationDecision::Allowed([REDACTED])")
            }
        }
    }
}

/// Authorization port that MUST run before retrieval.
#[async_trait]
pub trait ContextAuthorizationPort: Send + Sync {
    /// Decides whether the exact request may retrieve context.
    async fn authorize(
        &self,
        request: &ContextAuthorizationRequest,
    ) -> Result<ContextAuthorizationDecision, ContextAuthorizationError>;
}

/// The only retrieval request type, constructed after a successful authorization decision.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedContextRequest {
    identity: ContextIdentity,
    query: UntrustedText,
    deadline_epoch_ms: u64,
    authorization_id: AuthorizationId,
    grant_revision: PolicyRevisionId,
    scope_digest: ContentDigest,
}

impl AuthorizedContextRequest {
    /// Borrows tenant, principal, policy, and classification facts.
    #[must_use]
    pub const fn identity(&self) -> &ContextIdentity {
        &self.identity
    }

    /// Borrows the untrusted retrieval query.
    #[must_use]
    pub const fn query(&self) -> &UntrustedText {
        &self.query
    }

    /// Returns the absolute caller deadline in Unix milliseconds.
    #[must_use]
    pub const fn deadline_epoch_ms(&self) -> u64 {
        self.deadline_epoch_ms
    }

    /// Borrows the authorization-decision identifier.
    #[must_use]
    pub const fn authorization_id(&self) -> &AuthorizationId {
        &self.authorization_id
    }

    /// Borrows the exact grant revision.
    #[must_use]
    pub const fn grant_revision(&self) -> &PolicyRevisionId {
        &self.grant_revision
    }

    /// Returns the digest binding tenant, principal, policy, grant, and classification facts.
    #[must_use]
    pub const fn scope_digest(&self) -> ContentDigest {
        self.scope_digest
    }
}

impl fmt::Debug for AuthorizedContextRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedContextRequest([REDACTED])")
    }
}

/// Provenance category for untrusted retrieved data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSourceKind {
    /// An authorized internal document.
    Document,
    /// Authorized web content.
    Web,
    /// Output returned by a tool.
    ToolOutput,
    /// Output returned by another model.
    ModelOutput,
}

/// Trust domain retained on every assembled value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustDomain {
    /// Trusted application-authored instructions.
    PrivilegedInstruction,
    /// Caller, retrieval, tool, web, or model data that cannot become instructions.
    UntrustedData,
}

/// Authorization- and content-bound provenance for one retrieved record.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextProvenance {
    source_kind: ContextSourceKind,
    source_id: SourceId,
    source_revision: SourceRevisionId,
    content_digest: ContentDigest,
    authorization_id: AuthorizationId,
    policy_revision: PolicyRevisionId,
    authorized_scope_digest: ContentDigest,
}

impl ContextProvenance {
    /// Creates complete retrieval provenance.
    #[must_use]
    pub const fn new(
        source_kind: ContextSourceKind,
        source_id: SourceId,
        source_revision: SourceRevisionId,
        content_digest: ContentDigest,
        authorization_id: AuthorizationId,
        policy_revision: PolicyRevisionId,
        authorized_scope_digest: ContentDigest,
    ) -> Self {
        Self {
            source_kind,
            source_id,
            source_revision,
            content_digest,
            authorization_id,
            policy_revision,
            authorized_scope_digest,
        }
    }

    /// Returns the source category.
    #[must_use]
    pub const fn source_kind(&self) -> ContextSourceKind {
        self.source_kind
    }

    /// Borrows the source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Borrows the exact source revision.
    #[must_use]
    pub const fn source_revision(&self) -> &SourceRevisionId {
        &self.source_revision
    }

    /// Returns the source content digest.
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }

    /// Borrows the authorization-decision identifier.
    #[must_use]
    pub const fn authorization_id(&self) -> &AuthorizationId {
        &self.authorization_id
    }

    /// Borrows the policy revision used to authorize retrieval.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevisionId {
        &self.policy_revision
    }

    /// Returns the digest of the complete authorized scope.
    #[must_use]
    pub const fn authorized_scope_digest(&self) -> ContentDigest {
        self.authorized_scope_digest
    }

    /// Returns the fixed trust domain for retrieved context.
    #[must_use]
    pub const fn trust_domain(&self) -> TrustDomain {
        TrustDomain::UntrustedData
    }
}

impl fmt::Debug for ContextProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextProvenance")
            .field("source_kind", &self.source_kind)
            .field("source_id", &"[REDACTED]")
            .field("source_revision", &"[REDACTED]")
            .field("content_digest", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("trust_domain", &self.trust_domain())
            .finish_non_exhaustive()
    }
}

/// One authorized record that remains untrusted data after assembly.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextRecord {
    provenance: ContextProvenance,
    classification: DataClassification,
    priority: i32,
    content: UntrustedText,
}

impl ContextRecord {
    /// Creates a record only when its provenance digest matches its content.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ProvenanceMismatch`] for a digest mismatch.
    pub fn new(
        provenance: ContextProvenance,
        classification: DataClassification,
        priority: i32,
        content: UntrustedText,
    ) -> Result<Self, ContextError> {
        if provenance.content_digest() != ContentDigest::of(content.as_str().as_bytes()) {
            return Err(ContextError::ProvenanceMismatch);
        }
        Ok(Self {
            provenance,
            classification,
            priority,
            content,
        })
    }

    /// Borrows complete authorization and source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContextProvenance {
        &self.provenance
    }

    /// Returns the source category.
    #[must_use]
    pub const fn source_kind(&self) -> ContextSourceKind {
        self.provenance.source_kind()
    }

    /// Returns the fixed trust domain for retrieved context.
    #[must_use]
    pub const fn trust_domain(&self) -> TrustDomain {
        TrustDomain::UntrustedData
    }

    /// Returns the record classification.
    #[must_use]
    pub const fn classification(&self) -> DataClassification {
        self.classification
    }

    /// Returns the explicit ordering priority; larger values sort first.
    #[must_use]
    pub const fn priority(&self) -> i32 {
        self.priority
    }

    /// Borrows untrusted content.
    #[must_use]
    pub const fn content(&self) -> &UntrustedText {
        &self.content
    }
}

impl fmt::Debug for ContextRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextRecord")
            .field("provenance", &self.provenance)
            .field("classification", &self.classification)
            .field("priority", &self.priority)
            .field("content", &self.content)
            .finish()
    }
}

/// A retrieval result bounded before it crosses the port boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct RetrievedContextBatch {
    records: Vec<ContextRecord>,
}

impl RetrievedContextBatch {
    /// Validates and owns a bounded retrieval result.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::RetrievalLimit`] above 1,024 records or four MiB of content.
    pub fn new(records: Vec<ContextRecord>) -> Result<Self, ContextError> {
        let total_bytes = records.iter().try_fold(0_usize, |total, record| {
            total.checked_add(record.content().len())
        });
        if records.len() > MAX_RETRIEVED_RECORDS
            || total_bytes.is_none_or(|total| total > MAX_RETRIEVED_BYTES)
        {
            return Err(ContextError::RetrievalLimit);
        }
        Ok(Self { records })
    }

    /// Borrows the bounded records in adapter order.
    #[must_use]
    pub fn records(&self) -> &[ContextRecord] {
        &self.records
    }

    fn into_records(self) -> Vec<ContextRecord> {
        self.records
    }
}

impl fmt::Debug for RetrievedContextBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievedContextBatch")
            .field("record_count", &self.records.len())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Retrieval port that cannot be invoked by the assembler without authorization facts.
#[async_trait]
pub trait ContextRetrievalPort: Send + Sync {
    /// Returns bounded, provenance-bearing records for an already-authorized request.
    async fn retrieve(
        &self,
        request: &AuthorizedContextRequest,
    ) -> Result<RetrievedContextBatch, ContextRetrievalError>;
}

/// Explicit reason that deterministic whole-record prefix selection stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TruncationReason {
    /// The record-count budget was exhausted.
    RecordCount,
    /// The next whole record exceeded the per-record byte boundary.
    RecordBytes,
    /// The next whole record exceeded the total byte budget.
    TotalBytes,
    /// The next whole record exceeded the deterministic token estimate budget.
    EstimatedTokens,
}

/// Redacted, deterministic context-selection manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextManifest {
    authorization_id: AuthorizationId,
    policy_revision: PolicyRevisionId,
    authorized_scope_digest: ContentDigest,
    ordered_provenance: Vec<ContextProvenance>,
    selected_bytes: usize,
    estimated_tokens: usize,
    truncation_reason: Option<TruncationReason>,
    omitted_records: usize,
}

impl ContextManifest {
    /// Borrows the authorization-decision identifier.
    #[must_use]
    pub const fn authorization_id(&self) -> &AuthorizationId {
        &self.authorization_id
    }

    /// Borrows the exact authorization policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevisionId {
        &self.policy_revision
    }

    /// Returns the authorized scope digest.
    #[must_use]
    pub const fn authorized_scope_digest(&self) -> ContentDigest {
        self.authorized_scope_digest
    }

    /// Borrows provenance in the exact selected order.
    #[must_use]
    pub fn ordered_provenance(&self) -> &[ContextProvenance] {
        &self.ordered_provenance
    }

    /// Returns selected UTF-8 bytes.
    #[must_use]
    pub const fn selected_bytes(&self) -> usize {
        self.selected_bytes
    }

    /// Returns the deterministic conservative token estimate `ceil(bytes / 4)` per record.
    #[must_use]
    pub const fn estimated_tokens(&self) -> usize {
        self.estimated_tokens
    }

    /// Returns why selection stopped, if every record fit.
    #[must_use]
    pub const fn truncation_reason(&self) -> Option<TruncationReason> {
        self.truncation_reason
    }

    /// Returns the number of records excluded after the prefix boundary.
    #[must_use]
    pub const fn omitted_records(&self) -> usize {
        self.omitted_records
    }

    /// Hashes the full ordered, truncated manifest for cache-key binding.
    #[must_use]
    pub fn semantic_digest(&self) -> ContentDigest {
        let mut bytes = Vec::with_capacity(256);
        append_part(&mut bytes, self.authorization_id.as_str().as_bytes());
        append_part(&mut bytes, self.policy_revision.as_str().as_bytes());
        append_part(&mut bytes, self.authorized_scope_digest.as_bytes());
        append_u64(&mut bytes, self.selected_bytes as u64);
        append_u64(&mut bytes, self.estimated_tokens as u64);
        append_u64(&mut bytes, self.omitted_records as u64);
        bytes.push(self.truncation_reason.map_or(0, |reason| reason as u8 + 1));
        for provenance in &self.ordered_provenance {
            bytes.push(provenance.source_kind() as u8);
            append_part(&mut bytes, provenance.source_id().as_str().as_bytes());
            append_part(&mut bytes, provenance.source_revision().as_str().as_bytes());
            append_part(&mut bytes, provenance.content_digest().as_bytes());
        }
        ContentDigest::of(&bytes)
    }
}

impl fmt::Debug for ContextManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextManifest")
            .field("authorization", &"[REDACTED]")
            .field("record_count", &self.ordered_provenance.len())
            .field("selected_bytes", &self.selected_bytes)
            .field("estimated_tokens", &self.estimated_tokens)
            .field("truncation_reason", &self.truncation_reason)
            .field("omitted_records", &self.omitted_records)
            .finish_non_exhaustive()
    }
}

/// Deterministically ordered authorized records that remain an untrusted-data channel.
#[derive(Clone, Eq, PartialEq)]
pub struct AssembledContext {
    records: Vec<ContextRecord>,
    manifest: ContextManifest,
}

impl AssembledContext {
    /// Borrows selected records in deterministic order.
    #[must_use]
    pub fn records(&self) -> &[ContextRecord] {
        &self.records
    }

    /// Borrows the complete redacted selection manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ContextManifest {
        &self.manifest
    }

    /// Returns the fixed trust domain of every assembled record.
    #[must_use]
    pub const fn trust_domain(&self) -> TrustDomain {
        TrustDomain::UntrustedData
    }
}

impl fmt::Debug for AssembledContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssembledContext")
            .field("record_count", &self.records.len())
            .field("manifest", &self.manifest)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Authorization-before-retrieval deterministic context orchestrator.
#[derive(Debug)]
pub struct ContextAssembler<A, R> {
    authorizer: A,
    retriever: R,
}

impl<A, R> ContextAssembler<A, R>
where
    A: ContextAuthorizationPort,
    R: ContextRetrievalPort,
{
    /// Creates an assembler from explicit authorization and retrieval ports.
    #[must_use]
    pub const fn new(authorizer: A, retriever: R) -> Self {
        Self {
            authorizer,
            retriever,
        }
    }

    /// Authorizes, retrieves, verifies provenance, sorts, and selects a whole-record prefix.
    ///
    /// Ordering is `priority DESC, source_kind ASC, source_id ASC, source_revision ASC,
    /// content_digest ASC`. Selection stops at the first record that would exceed any budget.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContextAssemblyError`] and never invokes retrieval after a denial or
    /// authorization failure.
    #[allow(
        clippy::too_many_lines,
        reason = "authorization, provenance verification, deterministic ordering, and truncation form one auditable policy"
    )]
    pub async fn assemble(
        &self,
        request: ContextAuthorizationRequest,
        budget: ContextBudget,
    ) -> Result<AssembledContext, ContextAssemblyError> {
        let decision = self
            .authorizer
            .authorize(&request)
            .await
            .map_err(|_| ContextAssemblyError::AuthorizationUnavailable)?;
        let ContextAuthorizationDecision::Allowed {
            authorization_id,
            grant_revision,
        } = decision
        else {
            return Err(ContextAssemblyError::Denied);
        };
        let scope_digest =
            authorized_scope_digest(request.identity(), &authorization_id, &grant_revision);
        let authorized = AuthorizedContextRequest {
            identity: request.identity,
            query: request.query,
            deadline_epoch_ms: request.deadline_epoch_ms,
            authorization_id,
            grant_revision,
            scope_digest,
        };
        let mut records = self
            .retriever
            .retrieve(&authorized)
            .await
            .map_err(|_| ContextAssemblyError::RetrievalUnavailable)?
            .into_records();
        for record in &records {
            let provenance = record.provenance();
            if provenance.authorization_id() != authorized.authorization_id()
                || provenance.policy_revision() != authorized.identity().policy_revision()
                || provenance.authorized_scope_digest() != authorized.scope_digest()
                || record.classification() > authorized.identity().maximum_classification()
            {
                return Err(ContextAssemblyError::ProvenanceMismatch);
            }
        }
        records.sort_by(|left, right| {
            (
                Reverse(left.priority()),
                left.source_kind(),
                left.provenance().source_id().as_str(),
                left.provenance().source_revision().as_str(),
                left.provenance().content_digest(),
            )
                .cmp(&(
                    Reverse(right.priority()),
                    right.source_kind(),
                    right.provenance().source_id().as_str(),
                    right.provenance().source_revision().as_str(),
                    right.provenance().content_digest(),
                ))
        });
        let mut source_versions = BTreeSet::new();
        for record in &records {
            let key = (
                record.source_kind(),
                record.provenance().source_id().as_str(),
                record.provenance().source_revision().as_str(),
            );
            if !source_versions.insert(key) {
                return Err(ContextAssemblyError::DuplicateProvenance);
            }
        }

        let total_records = records.len();
        let mut selected = Vec::with_capacity(total_records.min(budget.max_records));
        let mut selected_bytes = 0_usize;
        let mut estimated_tokens = 0_usize;
        let mut truncation_reason = None;
        for record in records {
            let record_bytes = record.content().len();
            let record_tokens = record_bytes.div_ceil(TOKEN_BYTES);
            let reason = if selected.len() >= budget.max_records {
                Some(TruncationReason::RecordCount)
            } else if record_bytes > budget.max_record_bytes {
                Some(TruncationReason::RecordBytes)
            } else if selected_bytes
                .checked_add(record_bytes)
                .is_none_or(|next| next > budget.max_total_bytes)
            {
                Some(TruncationReason::TotalBytes)
            } else if estimated_tokens
                .checked_add(record_tokens)
                .is_none_or(|next| next > budget.max_estimated_tokens)
            {
                Some(TruncationReason::EstimatedTokens)
            } else {
                None
            };
            if let Some(reason) = reason {
                truncation_reason = Some(reason);
                break;
            }
            selected_bytes += record_bytes;
            estimated_tokens += record_tokens;
            selected.push(record);
        }
        let omitted_records = total_records - selected.len();
        let ordered_provenance = selected
            .iter()
            .map(|record| record.provenance().clone())
            .collect();
        let manifest = ContextManifest {
            authorization_id: authorized.authorization_id,
            policy_revision: authorized.identity.policy_revision,
            authorized_scope_digest: authorized.scope_digest,
            ordered_provenance,
            selected_bytes,
            estimated_tokens,
            truncation_reason,
            omitted_records,
        };
        Ok(AssembledContext {
            records: selected,
            manifest,
        })
    }
}

/// Value-free authorization adapter failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextAuthorizationError {
    /// The authorization service was unavailable.
    #[error("context authorization is unavailable")]
    Unavailable,
}

/// Value-free retrieval adapter failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextRetrievalError {
    /// The retrieval service was unavailable.
    #[error("context retrieval is unavailable")]
    Unavailable,
}

/// Value-free context value construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    /// Context limits were zero or exceeded hard ceilings.
    #[error("context budget is invalid")]
    InvalidBudget,
    /// The caller deadline was zero.
    #[error("context deadline is invalid")]
    InvalidDeadline,
    /// A record content digest did not match its provenance.
    #[error("context provenance does not match content")]
    ProvenanceMismatch,
    /// A retrieval adapter exceeded fixed record-count or content-byte boundaries.
    #[error("context retrieval result exceeds its limit")]
    RetrievalLimit,
}

/// Value-free context assembly failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextAssemblyError {
    /// Authorization denied retrieval.
    #[error("context retrieval is denied")]
    Denied,
    /// Authorization failed before retrieval.
    #[error("context authorization is unavailable")]
    AuthorizationUnavailable,
    /// Authorized retrieval failed.
    #[error("context retrieval is unavailable")]
    RetrievalUnavailable,
    /// A record was not bound to the exact authorized scope or classification ceiling.
    #[error("context provenance is invalid")]
    ProvenanceMismatch,
    /// More than one record claimed the same source and revision.
    #[error("context provenance is duplicated")]
    DuplicateProvenance,
}

fn authorized_scope_digest(
    identity: &ContextIdentity,
    authorization_id: &AuthorizationId,
    grant_revision: &PolicyRevisionId,
) -> ContentDigest {
    let mut bytes = Vec::with_capacity(256);
    append_part(&mut bytes, identity.tenant_id().as_str().as_bytes());
    append_part(&mut bytes, identity.principal_id().as_str().as_bytes());
    append_part(&mut bytes, identity.policy_revision().as_str().as_bytes());
    append_part(&mut bytes, grant_revision.as_str().as_bytes());
    append_part(&mut bytes, authorization_id.as_str().as_bytes());
    bytes.push(identity.maximum_classification() as u8);
    ContentDigest::of(&bytes)
}

fn append_part(output: &mut Vec<u8>, value: &[u8]) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}
