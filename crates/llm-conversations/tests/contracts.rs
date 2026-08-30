//! Conversation persistence, lifecycle, privacy, and ownership contracts.

use std::{collections::HashMap, error::Error, sync::Mutex};

use async_trait::async_trait;
use omnius_auth_core::{SubjectId, TenantId};
use omnius_jobs_core::JobId;
use omnius_llm_conversations::*;
use omnius_llm_core::{
    LlmInputPart, LlmMessage, MessageRole, ReasoningOutputPart, ReasoningRepresentation,
};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct OwnerKey {
    authorization: ConversationAuthorization,
    conversation_id: ConversationId,
}

impl OwnerKey {
    const fn new(
        authorization: ConversationAuthorization,
        conversation_id: ConversationId,
    ) -> Self {
        Self {
            authorization,
            conversation_id,
        }
    }
}

#[derive(Default)]
struct MemoryState {
    conversations: HashMap<OwnerKey, Conversation>,
    messages: HashMap<OwnerKey, Vec<ConversationMessage>>,
    provider_state: HashMap<(OwnerKey, ProviderStateId), ProviderStateRecord>,
    jobs: HashMap<(OwnerKey, JobId), DurableJobReferenceSnapshot>,
    fences: HashMap<OwnerKey, DeletionFenceEvent>,
    inventories: HashMap<(OwnerKey, RetentionInventoryEventId), RetentionInventoryEvent>,
}

#[derive(Default)]
struct MemoryConversationRepository {
    state: Mutex<MemoryState>,
}

impl MemoryConversationRepository {
    fn state(&self) -> Result<std::sync::MutexGuard<'_, MemoryState>, ConversationRepositoryError> {
        self.state
            .lock()
            .map_err(|_| ConversationRepositoryError::Unavailable)
    }
}

#[async_trait]
impl ConversationRepository for MemoryConversationRepository {
    async fn create_conversation(
        &self,
        authorization: &ConversationAuthorization,
        command: &CreateConversation,
    ) -> ConversationRepositoryResult<CreateConversationOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let mut state = self.state()?;
        if let Some(existing) = state.conversations.get(&key) {
            return Ok(if existing.created_at() == command.created_at() {
                CreateConversationOutcome::Replayed(existing.clone())
            } else {
                CreateConversationOutcome::IdempotencyConflict
            });
        }
        let conversation = Conversation::create(*authorization, command)
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        state.conversations.insert(key, conversation.clone());
        Ok(CreateConversationOutcome::Created(conversation))
    }

    async fn read_conversation(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: ConversationId,
    ) -> ConversationRepositoryResult<Option<Conversation>> {
        Ok(self
            .state()?
            .conversations
            .get(&OwnerKey::new(*authorization, conversation_id))
            .cloned())
    }

    async fn append_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &AppendMessage,
    ) -> ConversationRepositoryResult<AppendMessageOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(AppendMessageOutcome::NotFound);
        };
        if let Some(existing) = state.messages.get(&key).and_then(|messages| {
            messages
                .iter()
                .find(|item| item.message_id() == command.message_id())
        }) {
            return Ok(
                if existing.message() == command.message()
                    && existing.created_at() == command.created_at()
                {
                    AppendMessageOutcome::Replayed {
                        message: existing.clone(),
                        conversation_revision: conversation.revision(),
                    }
                } else {
                    AppendMessageOutcome::IdempotencyConflict
                },
            );
        }
        if conversation.is_deletion_fenced() {
            return Ok(AppendMessageOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(AppendMessageOutcome::VersionConflict);
        }
        let (next, sequence) = conversation
            .advance_append(command.created_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        let message = ConversationMessage::from_append(command, sequence);
        state.messages.entry(key).or_default().push(message.clone());
        state.conversations.insert(key, next.clone());
        Ok(AppendMessageOutcome::Appended {
            message,
            conversation_revision: next.revision(),
        })
    }

    async fn read_messages(
        &self,
        authorization: &ConversationAuthorization,
        request: MessagePageRequest,
    ) -> ConversationRepositoryResult<ReadMessagesOutcome> {
        let key = OwnerKey::new(*authorization, request.conversation_id());
        let state = self.state()?;
        if !state.conversations.contains_key(&key) {
            return Ok(ReadMessagesOutcome::NotFound);
        }
        let after = request.cursor().map(MessageCursor::after_sequence);
        let take = usize::from(request.limit().get()) + 1;
        let mut items = state
            .messages
            .get(&key)
            .into_iter()
            .flatten()
            .filter(|message| after.is_none_or(|sequence| message.sequence() > sequence))
            .take(take)
            .cloned()
            .collect::<Vec<_>>();
        let has_more = items.len() > usize::from(request.limit().get());
        if has_more {
            items.pop();
        }
        let page = MessagePage::new(request, items, has_more)
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        Ok(ReadMessagesOutcome::Found(page))
    }

    async fn update_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &UpdateMessage,
    ) -> ConversationRepositoryResult<UpdateMessageOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(UpdateMessageOutcome::NotFound);
        };
        if conversation.is_deletion_fenced() {
            return Ok(UpdateMessageOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(UpdateMessageOutcome::VersionConflict);
        }
        let Some(existing) = state
            .messages
            .get(&key)
            .and_then(|messages| {
                messages
                    .iter()
                    .find(|item| item.message_id() == command.message_id())
            })
            .cloned()
        else {
            return Ok(UpdateMessageOutcome::NotFound);
        };
        if existing.revision() != command.expected_message_revision() {
            return Ok(UpdateMessageOutcome::VersionConflict);
        }
        let revised = existing
            .revise(command)
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        let next = conversation
            .advance(command.updated_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        let messages = state
            .messages
            .get_mut(&key)
            .ok_or(ConversationRepositoryError::InvalidData)?;
        let stored = messages
            .iter_mut()
            .find(|item| item.message_id() == command.message_id())
            .ok_or(ConversationRepositoryError::InvalidData)?;
        *stored = revised.clone();
        state.conversations.insert(key, next.clone());
        Ok(UpdateMessageOutcome::Updated {
            message: revised,
            conversation_revision: next.revision(),
        })
    }

    async fn delete_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &DeleteMessage,
    ) -> ConversationRepositoryResult<DeleteMessageOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(DeleteMessageOutcome::NotFound);
        };
        if conversation.is_deletion_fenced() {
            return Ok(DeleteMessageOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(DeleteMessageOutcome::VersionConflict);
        }
        let Some(position) = state.messages.get(&key).and_then(|messages| {
            messages
                .iter()
                .position(|message| message.message_id() == command.message_id())
        }) else {
            return Ok(DeleteMessageOutcome::NotFound);
        };
        let revision_matches = state
            .messages
            .get(&key)
            .and_then(|messages| messages.get(position))
            .is_some_and(|message| message.revision() == command.expected_message_revision());
        if !revision_matches {
            return Ok(DeleteMessageOutcome::VersionConflict);
        }
        let next = conversation
            .advance(command.deleted_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        state
            .messages
            .get_mut(&key)
            .ok_or(ConversationRepositoryError::InvalidData)?
            .remove(position);
        state.conversations.insert(key, next.clone());
        Ok(DeleteMessageOutcome::Deleted {
            conversation_revision: next.revision(),
        })
    }

    async fn save_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        command: &SaveProviderState,
    ) -> ConversationRepositoryResult<SaveProviderStateOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let state_key = (key, command.state_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(SaveProviderStateOutcome::NotFound);
        };
        if let Some(existing) = state.provider_state.get(&state_key)
            && command.expected_state_revision().is_none()
        {
            return Ok(
                if existing.value() == command.value()
                    && existing.updated_at() == command.updated_at()
                {
                    SaveProviderStateOutcome::Replayed {
                        state: existing.clone(),
                        conversation_revision: conversation.revision(),
                    }
                } else {
                    SaveProviderStateOutcome::IdempotencyConflict
                },
            );
        }
        if conversation.is_deletion_fenced() {
            return Ok(SaveProviderStateOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(SaveProviderStateOutcome::VersionConflict);
        }
        let saved = match state.provider_state.get(&state_key) {
            Some(existing) if Some(existing.revision()) == command.expected_state_revision() => {
                existing
                    .revise(command)
                    .map_err(|_| ConversationRepositoryError::InvalidData)?
            }
            None if command.expected_state_revision().is_none() => {
                ProviderStateRecord::from_save(command)
                    .map_err(|_| ConversationRepositoryError::InvalidData)?
            }
            _ => return Ok(SaveProviderStateOutcome::VersionConflict),
        };
        let next = conversation
            .advance(command.updated_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        state.provider_state.insert(state_key, saved.clone());
        state.conversations.insert(key, next.clone());
        Ok(SaveProviderStateOutcome::Saved {
            state: saved,
            conversation_revision: next.revision(),
        })
    }

    async fn read_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: ConversationId,
        state_id: ProviderStateId,
    ) -> ConversationRepositoryResult<Option<ProviderStateRecord>> {
        let key = OwnerKey::new(*authorization, conversation_id);
        Ok(self.state()?.provider_state.get(&(key, state_id)).cloned())
    }

    async fn delete_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        command: &DeleteProviderState,
    ) -> ConversationRepositoryResult<DeleteProviderStateOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let state_key = (key, command.state_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(DeleteProviderStateOutcome::NotFound);
        };
        if conversation.is_deletion_fenced() {
            return Ok(DeleteProviderStateOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(DeleteProviderStateOutcome::VersionConflict);
        }
        let Some(existing) = state.provider_state.get(&state_key) else {
            return Ok(DeleteProviderStateOutcome::NotFound);
        };
        if existing.revision() != command.expected_state_revision() {
            return Ok(DeleteProviderStateOutcome::VersionConflict);
        }
        let next = conversation
            .advance(command.deleted_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        state.provider_state.remove(&state_key);
        state.conversations.insert(key, next.clone());
        Ok(DeleteProviderStateOutcome::Deleted {
            conversation_revision: next.revision(),
        })
    }

    async fn save_job_reference_snapshot(
        &self,
        authorization: &ConversationAuthorization,
        command: &SaveJobReferenceSnapshot,
    ) -> ConversationRepositoryResult<SaveJobReferenceSnapshotOutcome> {
        let snapshot = command.snapshot();
        let key = OwnerKey::new(*authorization, snapshot.conversation_id());
        let job_key = (key, snapshot.job_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(SaveJobReferenceSnapshotOutcome::NotFound);
        };
        if let Some(existing) = state.jobs.get(&job_key) {
            return Ok(if existing == snapshot {
                SaveJobReferenceSnapshotOutcome::Replayed {
                    snapshot: existing.clone(),
                    conversation_revision: conversation.revision(),
                }
            } else {
                SaveJobReferenceSnapshotOutcome::IdempotencyConflict
            });
        }
        if conversation.is_deletion_fenced() {
            return Ok(SaveJobReferenceSnapshotOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(SaveJobReferenceSnapshotOutcome::VersionConflict);
        }
        let next = conversation
            .advance(snapshot.captured_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        state.jobs.insert(job_key, snapshot.clone());
        state.conversations.insert(key, next.clone());
        Ok(SaveJobReferenceSnapshotOutcome::Saved {
            snapshot: snapshot.clone(),
            conversation_revision: next.revision(),
        })
    }

    async fn read_job_reference_snapshot(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: ConversationId,
        job_id: JobId,
    ) -> ConversationRepositoryResult<Option<DurableJobReferenceSnapshot>> {
        let key = OwnerKey::new(*authorization, conversation_id);
        Ok(self.state()?.jobs.get(&(key, job_id)).cloned())
    }

    async fn fence_conversation_deletion(
        &self,
        authorization: &ConversationAuthorization,
        command: FenceConversationDeletion,
    ) -> ConversationRepositoryResult<FenceConversationDeletionOutcome> {
        let key = OwnerKey::new(*authorization, command.conversation_id());
        let mut state = self.state()?;
        let Some(conversation) = state.conversations.get(&key).cloned() else {
            return Ok(FenceConversationDeletionOutcome::NotFound);
        };
        if let Some(event) = state.fences.get(&key) {
            return Ok(if event.matches_command(command) {
                FenceConversationDeletionOutcome::Replayed {
                    conversation,
                    event: *event,
                }
            } else if event.request_id() == command.request_id() {
                FenceConversationDeletionOutcome::IdempotencyConflict
            } else {
                FenceConversationDeletionOutcome::AlreadyFenced
            });
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(FenceConversationDeletionOutcome::VersionConflict);
        }
        let fenced = conversation
            .fence_deletion(command.request_id(), command.fenced_at())
            .map_err(|_| ConversationRepositoryError::InvalidData)?;
        let event = DeletionFenceEvent::new(
            DeletionFenceEventId::new(),
            *authorization,
            command,
            fenced.revision(),
        )
        .map_err(|_| ConversationRepositoryError::InvalidData)?;
        state.conversations.insert(key, fenced.clone());
        state.fences.insert(key, event);
        Ok(FenceConversationDeletionOutcome::Fenced {
            conversation: fenced,
            event,
        })
    }

    async fn record_retention_inventory(
        &self,
        authorization: &ConversationAuthorization,
        event: &RetentionInventoryEvent,
    ) -> ConversationRepositoryResult<RecordRetentionInventoryOutcome> {
        let key = OwnerKey::new(*authorization, event.conversation_id());
        let mut state = self.state()?;
        let Some(fence) = state.fences.get(&key) else {
            return Ok(RecordRetentionInventoryOutcome::NotFound);
        };
        if event.tenant_id() != authorization.tenant_id()
            || event.principal_id() != authorization.principal_id()
            || event.fence_event_id() != fence.event_id()
            || event.request_id() != fence.request_id()
        {
            return Ok(RecordRetentionInventoryOutcome::NotFound);
        }
        let inventory_key = (key, event.event_id());
        if let Some(existing) = state.inventories.get(&inventory_key) {
            return Ok(if existing == event {
                RecordRetentionInventoryOutcome::Replayed(existing.clone())
            } else {
                RecordRetentionInventoryOutcome::IdempotencyConflict
            });
        }
        state.inventories.insert(inventory_key, event.clone());
        Ok(RecordRetentionInventoryOutcome::Recorded(event.clone()))
    }

    async fn read_retention_inventory(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: ConversationId,
        fence_event_id: DeletionFenceEventId,
    ) -> ConversationRepositoryResult<Option<RetentionInventoryEvent>> {
        let key = OwnerKey::new(*authorization, conversation_id);
        let state = self.state()?;
        Ok(state
            .inventories
            .iter()
            .filter(|((owner, _), event)| *owner == key && event.fence_event_id() == fence_event_id)
            .map(|(_, event)| event)
            .max_by_key(|event| event.inventoried_at())
            .cloned())
    }
}

fn instant(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000) + time::Duration::seconds(seconds)
}

fn authorization() -> ConversationAuthorization {
    ConversationAuthorization::new(TenantId::new(), SubjectId::new())
}

fn canonical_message(text: &str) -> Result<LlmMessage, omnius_llm_core::ContractError> {
    LlmMessage::new(MessageRole::User, vec![LlmInputPart::text(text.to_owned())])
}

async fn create(
    repository: &MemoryConversationRepository,
    authorization: ConversationAuthorization,
    conversation_id: ConversationId,
) -> Result<Conversation, Box<dyn Error>> {
    let command = CreateConversation::new(conversation_id, instant(0))?;
    match repository
        .create_conversation(&authorization, &command)
        .await?
    {
        CreateConversationOutcome::Created(conversation) => Ok(conversation),
        _ => Err("unexpected create outcome".into()),
    }
}

#[tokio::test]
async fn repository_isolates_every_lookup_by_tenant_and_principal() -> Result<(), Box<dyn Error>> {
    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;

    let wrong_principal = ConversationAuthorization::new(owner.tenant_id(), SubjectId::new());
    let wrong_tenant = ConversationAuthorization::new(TenantId::new(), owner.principal_id());
    assert!(
        repository
            .read_conversation(&wrong_principal, conversation_id)
            .await?
            .is_none()
    );
    assert!(
        repository
            .read_conversation(&wrong_tenant, conversation_id)
            .await?
            .is_none()
    );

    let append = AppendMessage::new(
        conversation_id,
        ConversationMessageId::new(),
        ConversationRevision::INITIAL,
        canonical_message("private prompt")?,
        instant(1),
    )?;
    assert_eq!(
        repository.append_message(&wrong_principal, &append).await?,
        AppendMessageOutcome::NotFound
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_append_has_one_winner_and_exact_replay_is_idempotent()
-> Result<(), Box<dyn Error>> {
    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;
    let first = AppendMessage::new(
        conversation_id,
        ConversationMessageId::new(),
        ConversationRevision::INITIAL,
        canonical_message("first")?,
        instant(1),
    )?;
    let second = AppendMessage::new(
        conversation_id,
        ConversationMessageId::new(),
        ConversationRevision::INITIAL,
        canonical_message("second")?,
        instant(1),
    )?;

    let (left, right) = tokio::join!(
        repository.append_message(&owner, &first),
        repository.append_message(&owner, &second)
    );
    let left = left?;
    let right = right?;
    assert!(matches!(
        (&left, &right),
        (
            AppendMessageOutcome::Appended { .. },
            AppendMessageOutcome::VersionConflict
        ) | (
            AppendMessageOutcome::VersionConflict,
            AppendMessageOutcome::Appended { .. }
        )
    ));

    let winner = if matches!(left, AppendMessageOutcome::Appended { .. }) {
        &first
    } else {
        &second
    };
    assert!(matches!(
        repository.append_message(&owner, winner).await?,
        AppendMessageOutcome::Replayed { .. }
    ));
    let conflicting_replay = AppendMessage::new(
        conversation_id,
        winner.message_id(),
        ConversationRevision::INITIAL,
        canonical_message("different payload")?,
        instant(1),
    )?;
    assert_eq!(
        repository
            .append_message(&owner, &conflicting_replay)
            .await?,
        AppendMessageOutcome::IdempotencyConflict
    );
    Ok(())
}

#[tokio::test]
async fn message_pagination_is_bounded_ordered_and_conversation_scoped()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        MessagePageSize::new(0),
        Err(ConversationContractError::InvalidPagination)
    );
    assert_eq!(
        MessagePageSize::new(MAX_MESSAGE_PAGE_SIZE + 1),
        Err(ConversationContractError::InvalidPagination)
    );

    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;
    let mut revision = ConversationRevision::INITIAL;
    for (offset, content) in ["one", "two", "three"].into_iter().enumerate() {
        let command = AppendMessage::new(
            conversation_id,
            ConversationMessageId::new(),
            revision,
            canonical_message(content)?,
            instant(i64::try_from(offset + 1)?),
        )?;
        revision = match repository.append_message(&owner, &command).await? {
            AppendMessageOutcome::Appended {
                conversation_revision,
                ..
            } => conversation_revision,
            _ => return Err("unexpected append outcome".into()),
        };
    }

    let size = MessagePageSize::new(2)?;
    let first_request = MessagePageRequest::first(conversation_id, size);
    let first_page = match repository.read_messages(&owner, first_request).await? {
        ReadMessagesOutcome::Found(page) => page,
        ReadMessagesOutcome::NotFound => return Err("conversation not found".into()),
    };
    assert_eq!(first_page.items().len(), 2);
    let cursor = first_page.next_cursor().ok_or("missing cursor")?;
    let second_request = MessagePageRequest::after(conversation_id, cursor, size)?;
    let second_page = match repository.read_messages(&owner, second_request).await? {
        ReadMessagesOutcome::Found(page) => page,
        ReadMessagesOutcome::NotFound => return Err("conversation not found".into()),
    };
    assert_eq!(second_page.items().len(), 1);
    assert!(second_page.next_cursor().is_none());
    assert_eq!(
        MessagePageRequest::after(ConversationId::new(), cursor, size),
        Err(ConversationContractError::InvalidPagination)
    );
    Ok(())
}

#[tokio::test]
async fn update_and_delete_require_message_and_aggregate_revisions() -> Result<(), Box<dyn Error>> {
    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;
    let append = AppendMessage::new(
        conversation_id,
        ConversationMessageId::new(),
        ConversationRevision::INITIAL,
        canonical_message("original")?,
        instant(1),
    )?;
    let AppendMessageOutcome::Appended {
        message,
        conversation_revision: revision,
    } = repository.append_message(&owner, &append).await?
    else {
        return Err("unexpected append outcome".into());
    };

    let wrong_update = UpdateMessage::new(
        conversation_id,
        message.message_id(),
        revision,
        ConversationMessageRevision::from_u64(2)?,
        canonical_message("replacement")?,
        instant(2),
    )?;
    assert_eq!(
        repository.update_message(&owner, &wrong_update).await?,
        UpdateMessageOutcome::VersionConflict
    );
    let update = UpdateMessage::new(
        conversation_id,
        message.message_id(),
        revision,
        message.revision(),
        canonical_message("replacement")?,
        instant(2),
    )?;
    let UpdateMessageOutcome::Updated {
        message: updated,
        conversation_revision: revision,
    } = repository.update_message(&owner, &update).await?
    else {
        return Err("unexpected update outcome".into());
    };
    let stale_delete = DeleteMessage::new(
        conversation_id,
        updated.message_id(),
        ConversationRevision::from_u64(revision.get() - 1)?,
        updated.revision(),
        instant(3),
    )?;
    assert_eq!(
        repository.delete_message(&owner, &stale_delete).await?,
        DeleteMessageOutcome::VersionConflict
    );
    let delete = DeleteMessage::new(
        conversation_id,
        updated.message_id(),
        revision,
        updated.revision(),
        instant(3),
    )?;
    let DeleteMessageOutcome::Deleted {
        conversation_revision: revision,
    } = repository.delete_message(&owner, &delete).await?
    else {
        return Err("unexpected delete outcome".into());
    };
    let append_after_delete = AppendMessage::new(
        conversation_id,
        ConversationMessageId::new(),
        revision,
        canonical_message("after deletion")?,
        instant(4),
    )?;
    let AppendMessageOutcome::Appended {
        message: appended, ..
    } = repository
        .append_message(&owner, &append_after_delete)
        .await?
    else {
        return Err("unexpected append outcome".into());
    };
    assert_eq!(appended.sequence().get(), 2);
    Ok(())
}

#[test]
fn provider_state_rejects_plaintext_payloads_and_accepts_only_sanctioned_forms()
-> Result<(), Box<dyn Error>> {
    let rejected = EncryptedContinuationReference::new(
        r#"{"provider":"raw","hidden_reasoning":"secret"}"#,
        "key-1",
        1,
        ContinuationEncryptionAlgorithm::Aes256Gcm,
        CiphertextDigest::new([7; 32])?,
    );
    assert_eq!(
        rejected,
        Err(ConversationContractError::InvalidProviderState)
    );
    assert_eq!(
        EncryptedContinuationReference::new(
            "encrypted://",
            "key-1",
            1,
            ContinuationEncryptionAlgorithm::Aes256Gcm,
            CiphertextDigest::new([7; 32])?,
        ),
        Err(ConversationContractError::InvalidProviderState)
    );

    let summary_part = ReasoningOutputPart::new(
        "safe-summary".to_owned(),
        ReasoningRepresentation::Summary,
        "The response compared two documented options.".to_owned(),
    )?;
    let signature_part = ReasoningOutputPart::new(
        "safe-signature".to_owned(),
        ReasoningRepresentation::Signature,
        "c2lnbmF0dXJl".to_owned(),
    )?;
    let summary = SanctionedReasoningSummary::from_canonical(&summary_part, Some(&signature_part))?;
    let summary_state = ProviderStateValue::ReasoningSummary(summary);
    let opaque_part = ReasoningOutputPart::new(
        "opaque-state".to_owned(),
        ReasoningRepresentation::OpaqueEncrypted,
        "hidden chain of thought".to_owned(),
    )?;
    assert_eq!(
        SanctionedReasoningSummary::from_canonical(&opaque_part, None),
        Err(ConversationContractError::InvalidProviderState)
    );
    let encrypted = EncryptedContinuationReference::new(
        "encrypted://llm-continuations/tenant/object-7",
        "conversation-kek",
        3,
        ContinuationEncryptionAlgorithm::XChaCha20Poly1305,
        CiphertextDigest::new([9; 32])?,
    )?;
    assert_eq!(encrypted.key_revision(), 3);
    let encrypted_state = ProviderStateValue::EncryptedContinuation(encrypted);
    assert!(!format!("{summary_state:?}").contains("documented options"));
    assert!(!format!("{encrypted_state:?}").contains("object-7"));
    Ok(())
}

#[tokio::test]
async fn provider_state_operations_are_scoped_and_version_checked() -> Result<(), Box<dyn Error>> {
    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;
    let state_id = ProviderStateId::new();
    let encrypted = ProviderStateValue::EncryptedContinuation(EncryptedContinuationReference::new(
        "encrypted://llm-continuations/tenant/state-1",
        "conversation-kek",
        1,
        ContinuationEncryptionAlgorithm::Aes256Gcm,
        CiphertextDigest::new([3; 32])?,
    )?);
    let save = SaveProviderState::new(
        conversation_id,
        state_id,
        ConversationRevision::INITIAL,
        None,
        encrypted,
        instant(1),
    )?;
    let SaveProviderStateOutcome::Saved {
        state: stored,
        conversation_revision: revision,
    } = repository.save_provider_state(&owner, &save).await?
    else {
        return Err("unexpected provider-state save outcome".into());
    };
    assert_eq!(stored.revision(), ProviderStateRevision::INITIAL);

    let wrong_principal = ConversationAuthorization::new(owner.tenant_id(), SubjectId::new());
    assert!(
        repository
            .read_provider_state(&wrong_principal, conversation_id, state_id)
            .await?
            .is_none()
    );

    let summary_part = ReasoningOutputPart::new(
        "provider-summary".to_owned(),
        ReasoningRepresentation::Summary,
        "A provider-sanctioned concise summary.".to_owned(),
    )?;
    let replacement = ProviderStateValue::ReasoningSummary(
        SanctionedReasoningSummary::from_canonical(&summary_part, None)?,
    );
    let stale_save = SaveProviderState::new(
        conversation_id,
        state_id,
        ConversationRevision::INITIAL,
        Some(stored.revision()),
        replacement.clone(),
        instant(2),
    )?;
    assert_eq!(
        repository.save_provider_state(&owner, &stale_save).await?,
        SaveProviderStateOutcome::VersionConflict
    );
    let replace = SaveProviderState::new(
        conversation_id,
        state_id,
        revision,
        Some(stored.revision()),
        replacement,
        instant(2),
    )?;
    let SaveProviderStateOutcome::Saved {
        state: stored,
        conversation_revision: revision,
    } = repository.save_provider_state(&owner, &replace).await?
    else {
        return Err("unexpected provider-state replace outcome".into());
    };
    assert_eq!(stored.revision().get(), 2);

    let stale_delete = DeleteProviderState::new(
        conversation_id,
        state_id,
        revision,
        ProviderStateRevision::INITIAL,
        instant(3),
    )?;
    assert_eq!(
        repository
            .delete_provider_state(&owner, &stale_delete)
            .await?,
        DeleteProviderStateOutcome::VersionConflict
    );
    let delete = DeleteProviderState::new(
        conversation_id,
        state_id,
        revision,
        stored.revision(),
        instant(3),
    )?;
    assert!(matches!(
        repository.delete_provider_state(&owner, &delete).await?,
        DeleteProviderStateOutcome::Deleted { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn deletion_fence_is_idempotent_and_rejects_later_mutations() -> Result<(), Box<dyn Error>> {
    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;
    let request_id = DeletionRequestId::new();
    let command = FenceConversationDeletion::new(
        conversation_id,
        request_id,
        ConversationRevision::INITIAL,
        instant(1),
    )?;
    let FenceConversationDeletionOutcome::Fenced { event, .. } = repository
        .fence_conversation_deletion(&owner, command)
        .await?
    else {
        return Err("unexpected fence outcome".into());
    };
    assert!(matches!(
        repository
            .fence_conversation_deletion(&owner, command)
            .await?,
        FenceConversationDeletionOutcome::Replayed { .. }
    ));
    let altered_replay = FenceConversationDeletion::new(
        conversation_id,
        request_id,
        ConversationRevision::INITIAL,
        instant(2),
    )?;
    assert_eq!(
        repository
            .fence_conversation_deletion(&owner, altered_replay)
            .await?,
        FenceConversationDeletionOutcome::IdempotencyConflict
    );
    let other = FenceConversationDeletion::new(
        conversation_id,
        DeletionRequestId::new(),
        event.fenced_revision(),
        instant(2),
    )?;
    assert_eq!(
        repository
            .fence_conversation_deletion(&owner, other)
            .await?,
        FenceConversationDeletionOutcome::AlreadyFenced
    );
    let append = AppendMessage::new(
        conversation_id,
        ConversationMessageId::new(),
        event.fenced_revision(),
        canonical_message("must not persist")?,
        instant(2),
    )?;
    assert_eq!(
        repository.append_message(&owner, &append).await?,
        AppendMessageOutcome::DeletionFenced
    );

    let entries = RetentionTarget::ALL
        .into_iter()
        .map(|target| {
            RetentionInventoryEntry::new(target, 0, RetentionDisposition::PendingDeletion)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        RetentionInventoryEvent::new(
            RetentionInventoryEventId::new(),
            event,
            entries[..entries.len() - 1].to_vec(),
            instant(2),
        ),
        Err(ConversationContractError::InvalidRetentionEvent)
    );
    assert_eq!(
        RetentionInventoryEvent::new(
            RetentionInventoryEventId::new(),
            event,
            entries.clone(),
            instant(0),
        ),
        Err(ConversationContractError::InvalidTimeline)
    );
    let inventory =
        RetentionInventoryEvent::new(RetentionInventoryEventId::new(), event, entries, instant(2))?;
    assert!(matches!(
        repository
            .record_retention_inventory(&owner, &inventory)
            .await?,
        RecordRetentionInventoryOutcome::Recorded(_)
    ));
    assert!(matches!(
        repository
            .record_retention_inventory(&owner, &inventory)
            .await?,
        RecordRetentionInventoryOutcome::Replayed(_)
    ));
    Ok(())
}

#[tokio::test]
async fn durable_job_snapshot_owns_exact_immutable_definition_revisions()
-> Result<(), Box<dyn Error>> {
    let repository = MemoryConversationRepository::default();
    let owner = authorization();
    let conversation_id = ConversationId::new();
    create(&repository, owner, conversation_id).await?;
    let mut caller_prompt_id = String::from("support.prompt");
    let job_id = JobId::new();
    let snapshot = DurableJobReferenceSnapshot::new(
        conversation_id,
        job_id,
        PromptRevisionReference::new(
            PromptDefinitionId::new(caller_prompt_id.clone())?,
            DefinitionRevision::from_u64(7)?,
        ),
        RouteRevisionReference::new(
            RouteDefinitionId::new("support.route")?,
            DefinitionRevision::from_u64(11)?,
        ),
        Some(SchemaRevisionReference::new(
            SchemaDefinitionId::new("support.response")?,
            DefinitionRevision::from_u64(4)?,
        )),
        vec![ToolRevisionReference::new(
            ToolDefinitionId::new("tickets.lookup")?,
            DefinitionRevision::from_u64(9)?,
        )],
        instant(1),
    )?;
    caller_prompt_id.clear();
    caller_prompt_id.push_str("mutated");
    assert_eq!(snapshot.prompt().id().as_str(), "support.prompt");
    assert_eq!(snapshot.prompt().revision().get(), 7);
    assert_eq!(snapshot.route().revision().get(), 11);
    assert_eq!(
        snapshot.schema().ok_or("missing schema")?.revision().get(),
        4
    );
    assert_eq!(snapshot.tools()[0].revision().get(), 9);

    let save = SaveJobReferenceSnapshot::new(ConversationRevision::INITIAL, snapshot.clone());
    assert!(matches!(
        repository
            .save_job_reference_snapshot(&owner, &save)
            .await?,
        SaveJobReferenceSnapshotOutcome::Saved { .. }
    ));
    assert!(matches!(
        repository
            .save_job_reference_snapshot(&owner, &save)
            .await?,
        SaveJobReferenceSnapshotOutcome::Replayed { .. }
    ));
    let conflicting_snapshot = DurableJobReferenceSnapshot::new(
        conversation_id,
        job_id,
        PromptRevisionReference::new(
            PromptDefinitionId::new("support.prompt")?,
            DefinitionRevision::from_u64(8)?,
        ),
        snapshot.route().clone(),
        snapshot.schema().cloned(),
        snapshot.tools().to_vec(),
        instant(1),
    )?;
    let conflict =
        SaveJobReferenceSnapshot::new(ConversationRevision::INITIAL, conflicting_snapshot);
    assert_eq!(
        repository
            .save_job_reference_snapshot(&owner, &conflict)
            .await?,
        SaveJobReferenceSnapshotOutcome::IdempotencyConflict
    );
    Ok(())
}

#[test]
fn debug_and_errors_never_render_message_or_provider_content() -> Result<(), Box<dyn Error>> {
    let secret = "customer-secret-prompt-9381";
    let command = AppendMessage::new(
        ConversationId::new(),
        ConversationMessageId::new(),
        ConversationRevision::INITIAL,
        canonical_message(secret)?,
        instant(1),
    )?;
    assert!(!format!("{command:?}").contains(secret));

    let error = EncryptedContinuationReference::new(
        secret,
        "key",
        1,
        ContinuationEncryptionAlgorithm::Aes256Gcm,
        CiphertextDigest::new([1; 32])?,
    )
    .err()
    .ok_or("expected invalid reference")?;
    assert!(!format!("{error:?}").contains(secret));
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{:?}", ConversationRepositoryError::InvalidData).contains(secret));
    Ok(())
}
