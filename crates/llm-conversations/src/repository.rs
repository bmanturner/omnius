use async_trait::async_trait;
use omnius_jobs_core::JobId;
use thiserror::Error;

use crate::{
    AppendMessage, Conversation, ConversationAuthorization, ConversationMessage,
    ConversationRevision, CreateConversation, DeleteMessage, DeleteProviderState,
    DeletionFenceEvent, DurableJobReferenceSnapshot, FenceConversationDeletion, MessagePage,
    MessagePageRequest, ProviderStateRecord, RetentionInventoryEvent, SaveJobReferenceSnapshot,
    SaveProviderState, UpdateMessage,
};

/// Closed persistence failure categories that never contain conversation or provider content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConversationRepositoryError {
    /// The backing persistence service is unavailable.
    #[error("conversation repository is unavailable")]
    Unavailable,
    /// Persisted data violated the canonical domain contract.
    #[error("conversation repository data is invalid")]
    InvalidData,
    /// The operation exceeded its bounded persistence deadline.
    #[error("conversation repository operation timed out")]
    Timeout,
}

/// A repository result with a fixed content-free failure type.
pub type ConversationRepositoryResult<T> = Result<T, ConversationRepositoryError>;

/// Result of an idempotent conversation create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateConversationOutcome {
    /// A new conversation was inserted.
    Created(Conversation),
    /// The same conversation create was already applied.
    Replayed(Conversation),
    /// The stable identity exists with different immutable create facts.
    IdempotencyConflict,
}

/// Result of an atomic, version-checked message append.
#[derive(Clone, Debug, PartialEq)]
pub enum AppendMessageOutcome {
    /// The canonical message was appended and the aggregate revision advanced.
    Appended {
        /// The immutable persisted message snapshot.
        message: ConversationMessage,
        /// The immutable aggregate revision after append.
        conversation_revision: ConversationRevision,
    },
    /// The same message identity and canonical message were already appended.
    Replayed {
        /// The original immutable message snapshot.
        message: ConversationMessage,
        /// The current aggregate revision, which may have advanced after the original append.
        conversation_revision: ConversationRevision,
    },
    /// No conversation exists in the exact tenant and principal scope.
    NotFound,
    /// The expected aggregate revision did not match.
    VersionConflict,
    /// The message identity exists with different canonical content.
    IdempotencyConflict,
    /// A deletion fence prohibits every subsequent content mutation.
    DeletionFenced,
}

/// Result of reading one bounded message page.
#[derive(Clone, Debug, PartialEq)]
pub enum ReadMessagesOutcome {
    /// The conversation exists and the bounded page was returned.
    Found(MessagePage),
    /// No conversation exists in the exact tenant and principal scope.
    NotFound,
}

/// Result of an atomic message replacement.
#[derive(Clone, Debug, PartialEq)]
pub enum UpdateMessageOutcome {
    /// The message and aggregate each advanced by one immutable revision.
    Updated {
        /// The immutable replacement message snapshot.
        message: ConversationMessage,
        /// The immutable aggregate revision after update.
        conversation_revision: ConversationRevision,
    },
    /// No conversation or message exists in the exact tenant and principal scope.
    NotFound,
    /// The expected aggregate or message revision did not match.
    VersionConflict,
    /// A deletion fence prohibits every subsequent content mutation.
    DeletionFenced,
}

/// Result of an atomic message deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteMessageOutcome {
    /// The message was deleted and the aggregate revision advanced.
    Deleted {
        /// The immutable aggregate revision after deletion.
        conversation_revision: ConversationRevision,
    },
    /// No conversation or message exists in the exact tenant and principal scope.
    NotFound,
    /// The expected aggregate or message revision did not match.
    VersionConflict,
    /// A deletion fence prohibits every subsequent content mutation.
    DeletionFenced,
}

/// Result of an atomic sanctioned provider-state create or replacement.
#[derive(Clone, Debug, PartialEq)]
pub enum SaveProviderStateOutcome {
    /// Provider state was created or replaced and the aggregate revision advanced.
    Saved {
        /// The immutable sanctioned provider-state snapshot.
        state: ProviderStateRecord,
        /// The immutable aggregate revision after save.
        conversation_revision: ConversationRevision,
    },
    /// An exact create replay was recognized without another mutation.
    Replayed {
        /// The original immutable provider-state snapshot.
        state: ProviderStateRecord,
        /// The current aggregate revision.
        conversation_revision: ConversationRevision,
    },
    /// No conversation exists in the exact tenant and principal scope.
    NotFound,
    /// The expected aggregate or provider-state revision did not match.
    VersionConflict,
    /// The state identity exists with different content on a create replay.
    IdempotencyConflict,
    /// A deletion fence prohibits every subsequent provider-state mutation.
    DeletionFenced,
}

/// Result of an atomic sanctioned provider-state deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteProviderStateOutcome {
    /// Provider state was deleted and the aggregate revision advanced.
    Deleted {
        /// The immutable aggregate revision after deletion.
        conversation_revision: ConversationRevision,
    },
    /// No conversation or provider-state record exists in the exact authorization scope.
    NotFound,
    /// The expected aggregate or provider-state revision did not match.
    VersionConflict,
    /// A deletion fence prohibits every subsequent provider-state mutation.
    DeletionFenced,
}

/// Result of recording one immutable durable-job definition snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SaveJobReferenceSnapshotOutcome {
    /// The snapshot was inserted and the aggregate revision advanced.
    Saved {
        /// The immutable inserted snapshot.
        snapshot: DurableJobReferenceSnapshot,
        /// The immutable aggregate revision after insert.
        conversation_revision: ConversationRevision,
    },
    /// The identical job snapshot already exists.
    Replayed {
        /// The original immutable snapshot.
        snapshot: DurableJobReferenceSnapshot,
        /// The current aggregate revision.
        conversation_revision: ConversationRevision,
    },
    /// No conversation exists in the exact authorization scope.
    NotFound,
    /// The expected aggregate revision did not match.
    VersionConflict,
    /// The job identity exists with a different reference snapshot.
    IdempotencyConflict,
    /// A deletion fence prohibits recording new durable job references.
    DeletionFenced,
}

/// Result of an idempotent, irreversible conversation deletion fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FenceConversationDeletionOutcome {
    /// The conversation was fenced and its aggregate revision advanced.
    Fenced {
        /// The immutable fenced conversation snapshot.
        conversation: Conversation,
        /// The content-free durable fence event.
        event: DeletionFenceEvent,
    },
    /// The same deletion request had already created the same fence.
    Replayed {
        /// The immutable fenced conversation snapshot.
        conversation: Conversation,
        /// The original content-free fence event.
        event: DeletionFenceEvent,
    },
    /// The request identity matches an accepted fence but immutable command facts differ.
    IdempotencyConflict,
    /// Another deletion request already fenced the conversation.
    AlreadyFenced,
    /// No conversation exists in the exact authorization scope.
    NotFound,
    /// The expected aggregate revision did not match.
    VersionConflict,
}

/// Result of recording one immutable complete retention inventory event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordRetentionInventoryOutcome {
    /// The complete event was inserted.
    Recorded(RetentionInventoryEvent),
    /// The identical event had already been inserted.
    Replayed(RetentionInventoryEvent),
    /// No matching deletion fence exists in the exact authorization scope.
    NotFound,
    /// The event identity exists with different immutable facts.
    IdempotencyConflict,
}

/// Persistence-neutral asynchronous port for canonical conversation storage.
///
/// Every method requires both tenant and principal authorization facts. Implementations must
/// apply both facts in the same database statement as each read or mutation and must return
/// `NotFound`/`None` for cross-scope identities rather than reveal their existence. Append,
/// replacement, deletion, snapshot, and fence operations are atomic optimistic-concurrency
/// transactions. Provider wire types and raw provider payloads must never be accepted or stored.
#[async_trait]
pub trait ConversationRepository: Send + Sync {
    /// Creates one principal-owned conversation idempotently.
    async fn create_conversation(
        &self,
        authorization: &ConversationAuthorization,
        command: &CreateConversation,
    ) -> ConversationRepositoryResult<CreateConversationOutcome>;

    /// Reads one conversation only in the exact authorization scope.
    async fn read_conversation(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: crate::ConversationId,
    ) -> ConversationRepositoryResult<Option<Conversation>>;

    /// Atomically appends one canonical message and advances the aggregate revision.
    async fn append_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &AppendMessage,
    ) -> ConversationRepositoryResult<AppendMessageOutcome>;

    /// Reads one bounded keyset page only in the exact authorization scope.
    async fn read_messages(
        &self,
        authorization: &ConversationAuthorization,
        request: MessagePageRequest,
    ) -> ConversationRepositoryResult<ReadMessagesOutcome>;

    /// Atomically replaces one canonical message and advances both revisions.
    async fn update_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &UpdateMessage,
    ) -> ConversationRepositoryResult<UpdateMessageOutcome>;

    /// Atomically deletes one canonical message and advances the aggregate revision.
    async fn delete_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &DeleteMessage,
    ) -> ConversationRepositoryResult<DeleteMessageOutcome>;

    /// Atomically creates or replaces one sanctioned provider-state value.
    async fn save_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        command: &SaveProviderState,
    ) -> ConversationRepositoryResult<SaveProviderStateOutcome>;

    /// Reads one sanctioned provider-state value only in the exact authorization scope.
    async fn read_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: crate::ConversationId,
        state_id: crate::ProviderStateId,
    ) -> ConversationRepositoryResult<Option<ProviderStateRecord>>;

    /// Atomically deletes one sanctioned provider-state value.
    async fn delete_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        command: &DeleteProviderState,
    ) -> ConversationRepositoryResult<DeleteProviderStateOutcome>;

    /// Atomically records an immutable durable-job definition snapshot.
    async fn save_job_reference_snapshot(
        &self,
        authorization: &ConversationAuthorization,
        command: &SaveJobReferenceSnapshot,
    ) -> ConversationRepositoryResult<SaveJobReferenceSnapshotOutcome>;

    /// Reads one immutable durable-job definition snapshot in the exact authorization scope.
    async fn read_job_reference_snapshot(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: crate::ConversationId,
        job_id: JobId,
    ) -> ConversationRepositoryResult<Option<DurableJobReferenceSnapshot>>;

    /// Atomically and irreversibly fences one conversation for deletion.
    async fn fence_conversation_deletion(
        &self,
        authorization: &ConversationAuthorization,
        command: FenceConversationDeletion,
    ) -> ConversationRepositoryResult<FenceConversationDeletionOutcome>;

    /// Appends one complete immutable deletion/retention inventory event idempotently by event ID.
    async fn record_retention_inventory(
        &self,
        authorization: &ConversationAuthorization,
        event: &RetentionInventoryEvent,
    ) -> ConversationRepositoryResult<RecordRetentionInventoryOutcome>;

    /// Reads the most recent complete inventory event associated with one deletion fence.
    async fn read_retention_inventory(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: crate::ConversationId,
        fence_event_id: crate::DeletionFenceEventId,
    ) -> ConversationRepositoryResult<Option<RetentionInventoryEvent>>;
}
