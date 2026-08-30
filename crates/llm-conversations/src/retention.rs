use std::collections::BTreeSet;

use omnius_auth_core::{SubjectId, TenantId};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use time::OffsetDateTime;

use crate::{
    ConversationAuthorization, ConversationContractError, ConversationId, ConversationRevision,
    DeletionFenceEventId, DeletionRequestId, RetentionInventoryEventId,
    value::{validate_timeline, validate_utc},
};

/// A version-checked command that irreversibly fences one conversation for deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceConversationDeletion {
    conversation_id: ConversationId,
    request_id: DeletionRequestId,
    expected_conversation_revision: ConversationRevision,
    fenced_at: OffsetDateTime,
}

impl FenceConversationDeletion {
    /// Creates one idempotent deletion-fence command.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC fence instant.
    pub fn new(
        conversation_id: ConversationId,
        request_id: DeletionRequestId,
        expected_conversation_revision: ConversationRevision,
        fenced_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(fenced_at)?;
        Ok(Self {
            conversation_id,
            request_id,
            expected_conversation_revision,
            fenced_at,
        })
    }

    /// Returns the conversation to fence.
    #[must_use]
    pub const fn conversation_id(self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the deletion idempotency identity.
    #[must_use]
    pub const fn request_id(self) -> DeletionRequestId {
        self.request_id
    }

    /// Returns the expected aggregate revision.
    #[must_use]
    pub const fn expected_conversation_revision(self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Returns the UTC fence instant.
    #[must_use]
    pub const fn fenced_at(self) -> OffsetDateTime {
        self.fenced_at
    }
}

/// A content-free durable event proving that a deletion fence was accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DeletionFenceEvent {
    event_id: DeletionFenceEventId,
    request_id: DeletionRequestId,
    tenant_id: TenantId,
    principal_id: SubjectId,
    conversation_id: ConversationId,
    prior_revision: ConversationRevision,
    fenced_revision: ConversationRevision,
    fenced_at: OffsetDateTime,
}

impl DeletionFenceEvent {
    /// Creates a fence event whose revision is exactly one greater than the prior revision.
    ///
    /// # Errors
    ///
    /// Returns a content-free error for a non-UTC instant, exhausted prior revision, or a
    /// non-adjacent fenced revision.
    pub fn new(
        event_id: DeletionFenceEventId,
        authorization: ConversationAuthorization,
        command: FenceConversationDeletion,
        fenced_revision: ConversationRevision,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(command.fenced_at)?;
        if command.expected_conversation_revision.next()? != fenced_revision {
            return Err(ConversationContractError::InvalidRetentionEvent);
        }
        Ok(Self {
            event_id,
            request_id: command.request_id,
            tenant_id: authorization.tenant_id(),
            principal_id: authorization.principal_id(),
            conversation_id: command.conversation_id,
            prior_revision: command.expected_conversation_revision,
            fenced_revision,
            fenced_at: command.fenced_at,
        })
    }

    /// Returns the stable event identity.
    #[must_use]
    pub const fn event_id(self) -> DeletionFenceEventId {
        self.event_id
    }

    /// Returns the deletion idempotency identity.
    #[must_use]
    pub const fn request_id(self) -> DeletionRequestId {
        self.request_id
    }

    /// Returns the owning tenant identity.
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    /// Returns the authenticated principal that requested deletion.
    #[must_use]
    pub const fn principal_id(self) -> SubjectId {
        self.principal_id
    }

    /// Returns the fenced conversation identity.
    #[must_use]
    pub const fn conversation_id(self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the revision observed before fencing.
    #[must_use]
    pub const fn prior_revision(self) -> ConversationRevision {
        self.prior_revision
    }

    /// Returns the immutable revision created by fencing.
    #[must_use]
    pub const fn fenced_revision(self) -> ConversationRevision {
        self.fenced_revision
    }

    /// Returns the UTC fence instant.
    #[must_use]
    pub const fn fenced_at(self) -> OffsetDateTime {
        self.fenced_at
    }

    /// Reports whether a retry exactly matches the immutable accepted command facts.
    #[must_use]
    pub fn matches_command(self, command: FenceConversationDeletion) -> bool {
        self.request_id == command.request_id
            && self.conversation_id == command.conversation_id
            && self.prior_revision == command.expected_conversation_revision
            && self.fenced_at == command.fenced_at
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionFenceEventWire {
    event_id: DeletionFenceEventId,
    request_id: DeletionRequestId,
    tenant_id: TenantId,
    principal_id: SubjectId,
    conversation_id: ConversationId,
    prior_revision: ConversationRevision,
    fenced_revision: ConversationRevision,
    fenced_at: OffsetDateTime,
}

impl<'de> Deserialize<'de> for DeletionFenceEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DeletionFenceEventWire::deserialize(deserializer)?;
        let authorization = ConversationAuthorization::new(wire.tenant_id, wire.principal_id);
        let command = FenceConversationDeletion::new(
            wire.conversation_id,
            wire.request_id,
            wire.prior_revision,
            wire.fenced_at,
        )
        .map_err(D::Error::custom)?;
        Self::new(wire.event_id, authorization, command, wire.fenced_revision)
            .map_err(D::Error::custom)
    }
}

/// Closed row classes owned by the conversation repository's deletion inventory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionTarget {
    /// The owning conversation row and metadata.
    Conversation,
    /// Canonical conversation messages.
    Messages,
    /// Sanctioned reasoning summaries, signatures, and encrypted references.
    ProviderState,
    /// Immutable durable-job definition reference snapshots.
    JobReferenceSnapshots,
}

impl RetentionTarget {
    /// Every repository-owned target in deterministic order.
    ///
    /// Usage, media, cache, evaluation, and provider-side stores remain separate canonical
    /// privacy inventory adapters rather than a second inventory convention in this crate.
    pub const ALL: [Self; 4] = [
        Self::Conversation,
        Self::Messages,
        Self::ProviderState,
        Self::JobReferenceSnapshots,
    ];
}

/// The closed, content-free lifecycle state of one retention inventory target.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum RetentionDisposition {
    /// The target is inventoried and awaits deletion reconciliation.
    PendingDeletion,
    /// No matching records existed at inventory time.
    NoData,
    /// Reconciliation deleted every matching record.
    Deleted {
        /// UTC completion instant.
        completed_at: OffsetDateTime,
    },
    /// Records must remain until an exclusive lawful retention boundary.
    RetainedUntil {
        /// UTC exclusive retention boundary.
        retain_before: OffsetDateTime,
    },
}

/// One count and closed disposition in a deletion/retention inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetentionInventoryEntry {
    target: RetentionTarget,
    record_count: u64,
    disposition: RetentionDisposition,
}

impl RetentionInventoryEntry {
    /// Creates a content-free inventory entry.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidRetentionEvent`] when an embedded
    /// disposition timestamp is non-UTC or a no-data entry has a non-zero count.
    pub fn new(
        target: RetentionTarget,
        record_count: u64,
        disposition: RetentionDisposition,
    ) -> Result<Self, ConversationContractError> {
        match disposition {
            RetentionDisposition::Deleted { completed_at } => validate_utc(completed_at)?,
            RetentionDisposition::RetainedUntil { retain_before } => validate_utc(retain_before)?,
            RetentionDisposition::NoData if record_count != 0 => {
                return Err(ConversationContractError::InvalidRetentionEvent);
            }
            _ => {}
        }
        Ok(Self {
            target,
            record_count,
            disposition,
        })
    }

    /// Returns the closed inventory target.
    #[must_use]
    pub const fn target(self) -> RetentionTarget {
        self.target
    }

    /// Returns the content-free matching record count.
    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    /// Returns the closed lifecycle disposition.
    #[must_use]
    pub const fn disposition(self) -> RetentionDisposition {
        self.disposition
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionInventoryEntryWire {
    target: RetentionTarget,
    record_count: u64,
    disposition: RetentionDisposition,
}

impl<'de> Deserialize<'de> for RetentionInventoryEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RetentionInventoryEntryWire::deserialize(deserializer)?;
        Self::new(wire.target, wire.record_count, wire.disposition).map_err(D::Error::custom)
    }
}

/// A complete immutable deletion/retention inventory event for one accepted fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetentionInventoryEvent {
    event_id: RetentionInventoryEventId,
    fence_event_id: DeletionFenceEventId,
    request_id: DeletionRequestId,
    tenant_id: TenantId,
    principal_id: SubjectId,
    conversation_id: ConversationId,
    fenced_at: OffsetDateTime,
    entries: Vec<RetentionInventoryEntry>,
    inventoried_at: OffsetDateTime,
}

impl RetentionInventoryEvent {
    /// Creates a complete inventory containing each required target exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidRetentionEvent`] for a missing, duplicate,
    /// or extra target, or a content-free timeline error when inventory predates its fence.
    pub fn new(
        event_id: RetentionInventoryEventId,
        fence: DeletionFenceEvent,
        mut entries: Vec<RetentionInventoryEntry>,
        inventoried_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_timeline(fence.fenced_at, inventoried_at)?;
        let targets = entries
            .iter()
            .map(|entry| entry.target)
            .collect::<BTreeSet<_>>();
        let required = RetentionTarget::ALL.into_iter().collect::<BTreeSet<_>>();
        if entries.len() != RetentionTarget::ALL.len() || targets != required {
            return Err(ConversationContractError::InvalidRetentionEvent);
        }
        entries.sort_unstable_by_key(|entry| entry.target);
        Ok(Self {
            event_id,
            fence_event_id: fence.event_id,
            request_id: fence.request_id,
            tenant_id: fence.tenant_id,
            principal_id: fence.principal_id,
            conversation_id: fence.conversation_id,
            fenced_at: fence.fenced_at,
            entries,
            inventoried_at,
        })
    }

    /// Returns the stable inventory event identity.
    #[must_use]
    pub const fn event_id(&self) -> RetentionInventoryEventId {
        self.event_id
    }

    /// Returns the deletion fence event being inventoried.
    #[must_use]
    pub const fn fence_event_id(&self) -> DeletionFenceEventId {
        self.fence_event_id
    }

    /// Returns the deletion idempotency identity.
    #[must_use]
    pub const fn request_id(&self) -> DeletionRequestId {
        self.request_id
    }

    /// Returns the owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the authenticated requesting principal.
    #[must_use]
    pub const fn principal_id(&self) -> SubjectId {
        self.principal_id
    }

    /// Returns the conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the UTC deletion-fence instant that precedes this inventory.
    #[must_use]
    pub const fn fenced_at(&self) -> OffsetDateTime {
        self.fenced_at
    }

    /// Borrows the complete deterministic inventory entries.
    #[must_use]
    pub fn entries(&self) -> &[RetentionInventoryEntry] {
        &self.entries
    }

    /// Returns the UTC inventory instant.
    #[must_use]
    pub const fn inventoried_at(&self) -> OffsetDateTime {
        self.inventoried_at
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionInventoryEventWire {
    event_id: RetentionInventoryEventId,
    fence_event_id: DeletionFenceEventId,
    request_id: DeletionRequestId,
    tenant_id: TenantId,
    principal_id: SubjectId,
    conversation_id: ConversationId,
    fenced_at: OffsetDateTime,
    entries: Vec<RetentionInventoryEntry>,
    inventoried_at: OffsetDateTime,
}

impl<'de> Deserialize<'de> for RetentionInventoryEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut wire = RetentionInventoryEventWire::deserialize(deserializer)?;
        validate_timeline(wire.fenced_at, wire.inventoried_at).map_err(D::Error::custom)?;
        let targets = wire
            .entries
            .iter()
            .map(|entry| entry.target)
            .collect::<BTreeSet<_>>();
        let required = RetentionTarget::ALL.into_iter().collect::<BTreeSet<_>>();
        if wire.entries.len() != RetentionTarget::ALL.len() || targets != required {
            return Err(D::Error::custom(
                ConversationContractError::InvalidRetentionEvent,
            ));
        }
        wire.entries.sort_unstable_by_key(|entry| entry.target);
        Ok(Self {
            event_id: wire.event_id,
            fence_event_id: wire.fence_event_id,
            request_id: wire.request_id,
            tenant_id: wire.tenant_id,
            principal_id: wire.principal_id,
            conversation_id: wire.conversation_id,
            fenced_at: wire.fenced_at,
            entries: wire.entries,
            inventoried_at: wire.inventoried_at,
        })
    }
}
