use std::fmt;

use omnius_auth_core::{SubjectId, TenantId};
use omnius_llm_core::LlmMessage;
use serde::Serialize;
use time::OffsetDateTime;

use crate::{
    ConversationAuthorization, ConversationContractError, ConversationId, ConversationMessageId,
    ConversationMessageRevision, ConversationRevision, DeletionRequestId, MessageSequence,
    value::{validate_timeline, validate_utc},
};

/// The closed lifecycle state of one conversation aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConversationStatus {
    /// The conversation accepts version-checked mutations.
    Active,
    /// A deletion request fenced all subsequent content and provider-state mutations.
    DeletionFenced {
        /// The durable idempotency identity of the accepted deletion request.
        request_id: DeletionRequestId,
        /// The UTC instant at which the fence became effective.
        fenced_at: OffsetDateTime,
    },
}

/// An immutable snapshot of one tenant- and principal-owned conversation aggregate.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Conversation {
    id: ConversationId,
    tenant_id: TenantId,
    principal_id: SubjectId,
    revision: ConversationRevision,
    last_message_sequence: Option<MessageSequence>,
    status: ConversationStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Conversation {
    /// Creates an active conversation owned by the supplied authorization scope.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn create(
        authorization: ConversationAuthorization,
        command: &CreateConversation,
    ) -> Result<Self, ConversationContractError> {
        Self::restore(
            command.conversation_id,
            authorization.tenant_id(),
            authorization.principal_id(),
            ConversationRevision::INITIAL,
            None,
            ConversationStatus::Active,
            command.created_at,
            command.created_at,
        )
    }

    /// Restores a persisted immutable conversation snapshot after validating its timeline.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for non-UTC, decreasing, or
    /// internally inconsistent fence timestamps.
    #[allow(
        clippy::too_many_arguments,
        reason = "database restoration validates one complete immutable aggregate snapshot"
    )]
    pub fn restore(
        id: ConversationId,
        tenant_id: TenantId,
        principal_id: SubjectId,
        revision: ConversationRevision,
        last_message_sequence: Option<MessageSequence>,
        status: ConversationStatus,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_timeline(created_at, updated_at)?;
        if last_message_sequence.is_some_and(|sequence| revision.get() <= sequence.get()) {
            return Err(ConversationContractError::InvalidRevision);
        }
        if let ConversationStatus::DeletionFenced { fenced_at, .. } = status {
            validate_timeline(created_at, fenced_at)?;
            if fenced_at != updated_at {
                return Err(ConversationContractError::InvalidTimeline);
            }
        }
        Ok(Self {
            id,
            tenant_id,
            principal_id,
            revision,
            last_message_sequence,
            status,
            created_at,
            updated_at,
        })
    }

    /// Produces the next active aggregate revision after a content mutation.
    ///
    /// # Errors
    ///
    /// Returns a content-free error if the aggregate is fenced, the revision is exhausted,
    /// or `updated_at` is non-UTC or older than the prior snapshot.
    pub fn advance(&self, updated_at: OffsetDateTime) -> Result<Self, ConversationContractError> {
        if !matches!(self.status, ConversationStatus::Active) {
            return Err(ConversationContractError::InvalidRetentionEvent);
        }
        validate_timeline(self.updated_at, updated_at)?;
        Ok(Self {
            revision: self.revision.next()?,
            updated_at,
            ..self.clone()
        })
    }

    /// Produces the next active aggregate revision and a never-reused append position.
    ///
    /// # Errors
    ///
    /// Returns a content-free error if the aggregate is fenced, the revision or sequence is
    /// exhausted, or `appended_at` violates the aggregate timeline.
    pub fn advance_append(
        &self,
        appended_at: OffsetDateTime,
    ) -> Result<(Self, MessageSequence), ConversationContractError> {
        let sequence = match self.last_message_sequence {
            Some(sequence) => sequence.next()?,
            None => MessageSequence::from_u64(1)?,
        };
        let mut next = self.advance(appended_at)?;
        next.last_message_sequence = Some(sequence);
        Ok((next, sequence))
    }

    /// Produces the next aggregate revision with an irreversible deletion fence.
    ///
    /// # Errors
    ///
    /// Returns a content-free error if already fenced, the revision is exhausted, or the
    /// timestamp violates the aggregate timeline.
    pub fn fence_deletion(
        &self,
        request_id: DeletionRequestId,
        fenced_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        if !matches!(self.status, ConversationStatus::Active) {
            return Err(ConversationContractError::InvalidRetentionEvent);
        }
        validate_timeline(self.updated_at, fenced_at)?;
        Ok(Self {
            revision: self.revision.next()?,
            status: ConversationStatus::DeletionFenced {
                request_id,
                fenced_at,
            },
            updated_at: fenced_at,
            ..self.clone()
        })
    }

    /// Returns the stable conversation identity.
    #[must_use]
    pub const fn id(&self) -> ConversationId {
        self.id
    }

    /// Returns the owning tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the owning authenticated principal identity.
    #[must_use]
    pub const fn principal_id(&self) -> SubjectId {
        self.principal_id
    }

    /// Returns the immutable optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> ConversationRevision {
        self.revision
    }

    /// Returns the greatest message sequence ever allocated, including deleted messages.
    #[must_use]
    pub const fn last_message_sequence(&self) -> Option<MessageSequence> {
        self.last_message_sequence
    }

    /// Returns the closed lifecycle state.
    #[must_use]
    pub const fn status(&self) -> ConversationStatus {
        self.status
    }

    /// Returns the UTC creation instant.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the UTC last-mutation instant.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Reports whether all further content mutations must be rejected.
    #[must_use]
    pub const fn is_deletion_fenced(&self) -> bool {
        matches!(self.status, ConversationStatus::DeletionFenced { .. })
    }
}

impl fmt::Debug for Conversation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Conversation")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("revision", &self.revision)
            .field("last_message_sequence", &self.last_message_sequence)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// A command to create one principal-owned conversation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateConversation {
    conversation_id: ConversationId,
    created_at: OffsetDateTime,
}

impl CreateConversation {
    /// Creates a command with a caller-generated stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn new(
        conversation_id: ConversationId,
        created_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(created_at)?;
        Ok(Self {
            conversation_id,
            created_at,
        })
    }

    /// Returns the caller-generated conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the UTC creation instant.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// An immutable snapshot of one persisted canonical [`LlmMessage`].
#[derive(Clone, PartialEq, Serialize)]
pub struct ConversationMessage {
    conversation_id: ConversationId,
    message_id: ConversationMessageId,
    sequence: MessageSequence,
    revision: ConversationMessageRevision,
    message: LlmMessage,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl ConversationMessage {
    /// Materializes an initial message snapshot from a validated append command.
    #[must_use]
    pub fn from_append(command: &AppendMessage, sequence: MessageSequence) -> Self {
        Self {
            conversation_id: command.conversation_id,
            message_id: command.message_id,
            sequence,
            revision: ConversationMessageRevision::INITIAL,
            message: command.message.clone(),
            created_at: command.created_at,
            updated_at: command.created_at,
        }
    }

    /// Restores a persisted canonical message snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC or decreasing
    /// timeline.
    pub fn restore(
        conversation_id: ConversationId,
        message_id: ConversationMessageId,
        sequence: MessageSequence,
        revision: ConversationMessageRevision,
        message: LlmMessage,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_timeline(created_at, updated_at)?;
        Ok(Self {
            conversation_id,
            message_id,
            sequence,
            revision,
            message,
            created_at,
            updated_at,
        })
    }

    /// Produces the next immutable message snapshot from a matching update command.
    ///
    /// # Errors
    ///
    /// Returns a content-free error for mismatched identity/revision, revision exhaustion,
    /// or an invalid timeline.
    pub fn revise(&self, command: &UpdateMessage) -> Result<Self, ConversationContractError> {
        if command.conversation_id != self.conversation_id
            || command.message_id != self.message_id
            || command.expected_message_revision != self.revision
        {
            return Err(ConversationContractError::InvalidRevision);
        }
        validate_timeline(self.updated_at, command.updated_at)?;
        Ok(Self {
            revision: self.revision.next()?,
            message: command.message.clone(),
            updated_at: command.updated_at,
            ..self.clone()
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the stable message identity.
    #[must_use]
    pub const fn message_id(&self) -> ConversationMessageId {
        self.message_id
    }

    /// Returns the stable append position.
    #[must_use]
    pub const fn sequence(&self) -> MessageSequence {
        self.sequence
    }

    /// Returns the immutable message revision.
    #[must_use]
    pub const fn revision(&self) -> ConversationMessageRevision {
        self.revision
    }

    /// Borrows the provider-neutral canonical message.
    #[must_use]
    pub const fn message(&self) -> &LlmMessage {
        &self.message
    }

    /// Returns the UTC creation instant.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the UTC last-update instant.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

impl fmt::Debug for ConversationMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationMessage")
            .field("conversation_id", &self.conversation_id)
            .field("message_id", &self.message_id)
            .field("sequence", &self.sequence)
            .field("revision", &self.revision)
            .field("message", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A version-checked, idempotent append command containing one canonical message.
#[derive(Clone, PartialEq)]
pub struct AppendMessage {
    conversation_id: ConversationId,
    message_id: ConversationMessageId,
    expected_conversation_revision: ConversationRevision,
    message: LlmMessage,
    created_at: OffsetDateTime,
}

impl AppendMessage {
    /// Creates an append command.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn new(
        conversation_id: ConversationId,
        message_id: ConversationMessageId,
        expected_conversation_revision: ConversationRevision,
        message: LlmMessage,
        created_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(created_at)?;
        Ok(Self {
            conversation_id,
            message_id,
            expected_conversation_revision,
            message,
            created_at,
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the caller-generated idempotency identity.
    #[must_use]
    pub const fn message_id(&self) -> ConversationMessageId {
        self.message_id
    }

    /// Returns the expected aggregate revision.
    #[must_use]
    pub const fn expected_conversation_revision(&self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Borrows the canonical provider-neutral message.
    #[must_use]
    pub const fn message(&self) -> &LlmMessage {
        &self.message
    }

    /// Returns the UTC append instant.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

impl fmt::Debug for AppendMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppendMessage")
            .field("conversation_id", &self.conversation_id)
            .field("message_id", &self.message_id)
            .field(
                "expected_conversation_revision",
                &self.expected_conversation_revision,
            )
            .field("message", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A version-checked canonical message replacement command.
#[derive(Clone, PartialEq)]
pub struct UpdateMessage {
    conversation_id: ConversationId,
    message_id: ConversationMessageId,
    expected_conversation_revision: ConversationRevision,
    expected_message_revision: ConversationMessageRevision,
    message: LlmMessage,
    updated_at: OffsetDateTime,
}

impl UpdateMessage {
    /// Creates a canonical message update command.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn new(
        conversation_id: ConversationId,
        message_id: ConversationMessageId,
        expected_conversation_revision: ConversationRevision,
        expected_message_revision: ConversationMessageRevision,
        message: LlmMessage,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(updated_at)?;
        Ok(Self {
            conversation_id,
            message_id,
            expected_conversation_revision,
            expected_message_revision,
            message,
            updated_at,
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the stable message identity.
    #[must_use]
    pub const fn message_id(&self) -> ConversationMessageId {
        self.message_id
    }

    /// Returns the expected aggregate revision.
    #[must_use]
    pub const fn expected_conversation_revision(&self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Returns the expected message revision.
    #[must_use]
    pub const fn expected_message_revision(&self) -> ConversationMessageRevision {
        self.expected_message_revision
    }

    /// Borrows the replacement canonical provider-neutral message.
    #[must_use]
    pub const fn message(&self) -> &LlmMessage {
        &self.message
    }

    /// Returns the UTC update instant.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

impl fmt::Debug for UpdateMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateMessage")
            .field("conversation_id", &self.conversation_id)
            .field("message_id", &self.message_id)
            .field(
                "expected_conversation_revision",
                &self.expected_conversation_revision,
            )
            .field("expected_message_revision", &self.expected_message_revision)
            .field("message", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A version-checked command to delete one canonical message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteMessage {
    conversation_id: ConversationId,
    message_id: ConversationMessageId,
    expected_conversation_revision: ConversationRevision,
    expected_message_revision: ConversationMessageRevision,
    deleted_at: OffsetDateTime,
}

impl DeleteMessage {
    /// Creates a message deletion command.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn new(
        conversation_id: ConversationId,
        message_id: ConversationMessageId,
        expected_conversation_revision: ConversationRevision,
        expected_message_revision: ConversationMessageRevision,
        deleted_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(deleted_at)?;
        Ok(Self {
            conversation_id,
            message_id,
            expected_conversation_revision,
            expected_message_revision,
            deleted_at,
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the stable message identity.
    #[must_use]
    pub const fn message_id(&self) -> ConversationMessageId {
        self.message_id
    }

    /// Returns the expected aggregate revision.
    #[must_use]
    pub const fn expected_conversation_revision(&self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Returns the expected message revision.
    #[must_use]
    pub const fn expected_message_revision(&self) -> ConversationMessageRevision {
        self.expected_message_revision
    }

    /// Returns the UTC deletion instant.
    #[must_use]
    pub const fn deleted_at(&self) -> OffsetDateTime {
        self.deleted_at
    }
}
