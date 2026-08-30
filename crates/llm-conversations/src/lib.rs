//! Canonical LLM conversation domain, PostgreSQL repository, and asynchronous repository ports.
//!
//! Conversation persistence stores [`omnius_llm_core::LlmMessage`] directly and admits only
//! provider-sanctioned reasoning summaries/signatures or references to envelope-encrypted
//! continuation objects. Every repository operation requires an explicit tenant and principal.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod conversation;
mod job_snapshot;
mod pagination;
mod postgres;
mod privacy;
mod provider_state;
mod repository;
mod retention;
mod value;

pub use conversation::{
    AppendMessage, Conversation, ConversationMessage, ConversationStatus, CreateConversation,
    DeleteMessage, UpdateMessage,
};
pub use job_snapshot::{
    DurableJobReferenceSnapshot, PromptDefinitionId, PromptRevisionReference, RouteDefinitionId,
    RouteRevisionReference, SaveJobReferenceSnapshot, SchemaDefinitionId, SchemaRevisionReference,
    ToolDefinitionId, ToolRevisionReference,
};
pub use pagination::{
    MAX_MESSAGE_PAGE_SIZE, MessageCursor, MessagePage, MessagePageRequest, MessagePageSize,
};
pub use postgres::PostgresConversationRepository;
pub use privacy::{ConversationDataInventoryAdapter, ConversationInventoryRepository};
pub use provider_state::{
    CiphertextDigest, ContinuationEncryptionAlgorithm, DeleteProviderState,
    EncryptedContinuationReference, ProviderStateRecord, ProviderStateValue, ReasoningSignature,
    SanctionedReasoningSummary, SaveProviderState,
};
pub use repository::{
    AppendMessageOutcome, ConversationRepository, ConversationRepositoryError,
    ConversationRepositoryResult, CreateConversationOutcome, DeleteMessageOutcome,
    DeleteProviderStateOutcome, FenceConversationDeletionOutcome, ReadMessagesOutcome,
    RecordRetentionInventoryOutcome, SaveJobReferenceSnapshotOutcome, SaveProviderStateOutcome,
    UpdateMessageOutcome,
};
pub use retention::{
    DeletionFenceEvent, FenceConversationDeletion, RetentionDisposition, RetentionInventoryEntry,
    RetentionInventoryEvent, RetentionTarget,
};
pub use value::{
    ConversationAuthorization, ConversationContractError, ConversationId, ConversationMessageId,
    ConversationMessageRevision, ConversationRevision, DefinitionRevision, DeletionFenceEventId,
    DeletionRequestId, MessageSequence, ProviderStateId, ProviderStateRevision,
    RetentionInventoryEventId,
};
