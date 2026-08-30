use std::fmt;

use async_trait::async_trait;
use omnius_auth_core::{SubjectId, TenantId};
use omnius_jobs_core::JobId;
use omnius_llm_core::{LlmMessage, ReasoningOutputPart, ReasoningRepresentation};
use omnius_postgres::{PostgresError, PostgresPool};
use serde_json::Value;
use sqlx::{Connection as _, Postgres, Row as _, Transaction, postgres::PgRow};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AppendMessage, AppendMessageOutcome, CiphertextDigest, ContinuationEncryptionAlgorithm,
    Conversation, ConversationAuthorization, ConversationId, ConversationMessage,
    ConversationMessageId, ConversationMessageRevision, ConversationRepository,
    ConversationRepositoryError, ConversationRepositoryResult, ConversationRevision,
    ConversationStatus, CreateConversation, CreateConversationOutcome, DeleteMessage,
    DeleteMessageOutcome, DeleteProviderState, DeleteProviderStateOutcome, DeletionFenceEvent,
    DeletionFenceEventId, DeletionRequestId, DurableJobReferenceSnapshot,
    EncryptedContinuationReference, FenceConversationDeletion, FenceConversationDeletionOutcome,
    MessagePage, MessagePageRequest, MessageSequence, PromptDefinitionId, PromptRevisionReference,
    ProviderStateId, ProviderStateRecord, ProviderStateRevision, ProviderStateValue,
    ReadMessagesOutcome, ReasoningSignature, RecordRetentionInventoryOutcome,
    RetentionInventoryEntry, RetentionInventoryEvent, RetentionInventoryEventId, RouteDefinitionId,
    RouteRevisionReference, SanctionedReasoningSummary, SaveJobReferenceSnapshot,
    SaveJobReferenceSnapshotOutcome, SaveProviderState, SaveProviderStateOutcome,
    SchemaDefinitionId, SchemaRevisionReference, ToolRevisionReference, UpdateMessage,
    UpdateMessageOutcome,
};

/// SQLx-backed canonical conversation repository over the managed PostgreSQL pool.
#[derive(Clone)]
pub struct PostgresConversationRepository {
    pool: PostgresPool,
}

impl PostgresConversationRepository {
    /// Creates a repository over the shared managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Borrows the shared managed PostgreSQL pool.
    #[must_use]
    pub const fn pool(&self) -> &PostgresPool {
        &self.pool
    }
}

impl fmt::Debug for PostgresConversationRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresConversationRepository")
            .finish_non_exhaustive()
    }
}

fn map_pool(error: PostgresError) -> ConversationRepositoryError {
    match error {
        PostgresError::AcquireTimeout
        | PostgresError::ConnectTimeout
        | PostgresError::CloseTimeout => ConversationRepositoryError::Timeout,
        _ => ConversationRepositoryError::Unavailable,
    }
}

fn map_sqlx(error: sqlx::Error) -> ConversationRepositoryError {
    let mapped = match &error {
        sqlx::Error::PoolTimedOut => ConversationRepositoryError::Timeout,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("57014") => {
            ConversationRepositoryError::Timeout
        }
        _ => ConversationRepositoryError::Unavailable,
    };
    drop(error);
    mapped
}

const fn invalid_data() -> ConversationRepositoryError {
    ConversationRepositoryError::InvalidData
}

async fn set_scope(
    transaction: &mut Transaction<'_, Postgres>,
    authorization: &ConversationAuthorization,
) -> ConversationRepositoryResult<()> {
    sqlx::query(
        "SELECT set_config('app.tenant_id', $1::text, true), \
                set_config('app.principal_id', $2::text, true)",
    )
    .bind(authorization.tenant_id().as_uuid())
    .bind(authorization.principal_id().as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

fn positive_u64(value: i64) -> ConversationRepositoryResult<u64> {
    let value = u64::try_from(value).map_err(|_| invalid_data())?;
    if value == 0 {
        Err(invalid_data())
    } else {
        Ok(value)
    }
}

fn conversation_from_row(row: &PgRow) -> ConversationRepositoryResult<Conversation> {
    let tenant_id = TenantId::from_uuid(row.try_get("tenant_id").map_err(|_| invalid_data())?)
        .map_err(|_| invalid_data())?;
    let principal_id =
        SubjectId::from_uuid(row.try_get("principal_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?;
    let conversation_id =
        ConversationId::from_uuid(row.try_get("conversation_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?;
    let revision = ConversationRevision::from_u64(positive_u64(
        row.try_get("revision").map_err(|_| invalid_data())?,
    )?)
    .map_err(|_| invalid_data())?;
    let last_message_sequence = row
        .try_get::<Option<i64>, _>("last_message_sequence")
        .map_err(|_| invalid_data())?
        .map(positive_u64)
        .transpose()?
        .map(MessageSequence::from_u64)
        .transpose()
        .map_err(|_| invalid_data())?;
    let request_id = row
        .try_get::<Option<Uuid>, _>("deletion_request_id")
        .map_err(|_| invalid_data())?;
    let fenced_at = row
        .try_get::<Option<OffsetDateTime>, _>("fenced_at")
        .map_err(|_| invalid_data())?;
    let status = match (request_id, fenced_at) {
        (None, None) => ConversationStatus::Active,
        (Some(request_id), Some(fenced_at)) => ConversationStatus::DeletionFenced {
            request_id: DeletionRequestId::from_uuid(request_id).map_err(|_| invalid_data())?,
            fenced_at,
        },
        _ => return Err(invalid_data()),
    };
    Conversation::restore(
        conversation_id,
        tenant_id,
        principal_id,
        revision,
        last_message_sequence,
        status,
        row.try_get("created_at").map_err(|_| invalid_data())?,
        row.try_get("updated_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())
}

fn message_from_row(row: &PgRow) -> ConversationRepositoryResult<ConversationMessage> {
    let canonical: Value = row
        .try_get("canonical_message")
        .map_err(|_| invalid_data())?;
    let message: LlmMessage = serde_json::from_value(canonical).map_err(|_| invalid_data())?;
    ConversationMessage::restore(
        ConversationId::from_uuid(row.try_get("conversation_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        ConversationMessageId::from_uuid(row.try_get("message_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        MessageSequence::from_u64(positive_u64(
            row.try_get("sequence").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
        ConversationMessageRevision::from_u64(positive_u64(
            row.try_get("revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
        message,
        row.try_get("created_at").map_err(|_| invalid_data())?,
        row.try_get("updated_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())
}

struct ProviderColumns<'a> {
    kind: &'static str,
    summary: Option<&'a str>,
    signature: Option<&'a str>,
    encrypted_reference: Option<&'a str>,
    key_id: Option<&'a str>,
    key_revision: Option<i64>,
    algorithm: Option<&'static str>,
    ciphertext_digest: Option<CiphertextDigest>,
}

fn provider_columns(value: &ProviderStateValue) -> ProviderColumns<'_> {
    match value {
        ProviderStateValue::ReasoningSummary(summary) => ProviderColumns {
            kind: "reasoning_summary",
            summary: Some(summary.summary()),
            signature: summary.signature().map(ReasoningSignature::as_str),
            encrypted_reference: None,
            key_id: None,
            key_revision: None,
            algorithm: None,
            ciphertext_digest: None,
        },
        ProviderStateValue::EncryptedContinuation(reference) => ProviderColumns {
            kind: "encrypted_continuation",
            summary: None,
            signature: None,
            encrypted_reference: Some(reference.reference()),
            key_id: Some(reference.key_id()),
            key_revision: Some(i64::from(reference.key_revision())),
            algorithm: Some(match reference.algorithm() {
                ContinuationEncryptionAlgorithm::Aes256Gcm => "aes_256_gcm",
                ContinuationEncryptionAlgorithm::XChaCha20Poly1305 => "xchacha20_poly1305",
            }),
            ciphertext_digest: Some(reference.ciphertext_digest()),
        },
    }
}

fn provider_state_from_row(row: &PgRow) -> ConversationRepositoryResult<ProviderStateRecord> {
    let kind: String = row.try_get("state_kind").map_err(|_| invalid_data())?;
    let value = match kind.as_str() {
        "reasoning_summary" => {
            let summary = row
                .try_get::<Option<String>, _>("reasoning_summary")
                .map_err(|_| invalid_data())?
                .ok_or_else(invalid_data)?;
            let summary_part = ReasoningOutputPart::new(
                "persisted-summary".to_owned(),
                ReasoningRepresentation::Summary,
                summary,
            )
            .map_err(|_| invalid_data())?;
            let signature = row
                .try_get::<Option<String>, _>("reasoning_signature")
                .map_err(|_| invalid_data())?
                .map(|signature| {
                    ReasoningOutputPart::new(
                        "persisted-signature".to_owned(),
                        ReasoningRepresentation::Signature,
                        signature,
                    )
                    .map_err(|_| invalid_data())
                })
                .transpose()?;
            ProviderStateValue::ReasoningSummary(
                SanctionedReasoningSummary::from_canonical(&summary_part, signature.as_ref())
                    .map_err(|_| invalid_data())?,
            )
        }
        "encrypted_continuation" => {
            let digest = row
                .try_get::<Option<Vec<u8>>, _>("ciphertext_digest")
                .map_err(|_| invalid_data())?
                .ok_or_else(invalid_data)?;
            let digest: [u8; 32] = digest.try_into().map_err(|_| invalid_data())?;
            let key_revision = row
                .try_get::<Option<i64>, _>("encryption_key_revision")
                .map_err(|_| invalid_data())?
                .ok_or_else(invalid_data)?;
            let key_revision =
                u32::try_from(positive_u64(key_revision)?).map_err(|_| invalid_data())?;
            let algorithm = match row
                .try_get::<Option<String>, _>("encryption_algorithm")
                .map_err(|_| invalid_data())?
                .as_deref()
            {
                Some("aes_256_gcm") => ContinuationEncryptionAlgorithm::Aes256Gcm,
                Some("xchacha20_poly1305") => ContinuationEncryptionAlgorithm::XChaCha20Poly1305,
                _ => return Err(invalid_data()),
            };
            ProviderStateValue::EncryptedContinuation(
                EncryptedContinuationReference::new(
                    row.try_get::<Option<String>, _>("encrypted_reference")
                        .map_err(|_| invalid_data())?
                        .ok_or_else(invalid_data)?,
                    row.try_get::<Option<String>, _>("encryption_key_id")
                        .map_err(|_| invalid_data())?
                        .ok_or_else(invalid_data)?,
                    key_revision,
                    algorithm,
                    CiphertextDigest::new(digest).map_err(|_| invalid_data())?,
                )
                .map_err(|_| invalid_data())?,
            )
        }
        _ => return Err(invalid_data()),
    };
    ProviderStateRecord::restore(
        ConversationId::from_uuid(row.try_get("conversation_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        ProviderStateId::from_uuid(row.try_get("state_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        ProviderStateRevision::from_u64(positive_u64(
            row.try_get("revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
        value,
        row.try_get("created_at").map_err(|_| invalid_data())?,
        row.try_get("updated_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())
}

fn job_snapshot_from_row(row: &PgRow) -> ConversationRepositoryResult<DurableJobReferenceSnapshot> {
    let prompt = PromptRevisionReference::new(
        PromptDefinitionId::new(
            row.try_get::<String, _>("prompt_definition_id")
                .map_err(|_| invalid_data())?,
        )
        .map_err(|_| invalid_data())?,
        crate::DefinitionRevision::from_u64(positive_u64(
            row.try_get("prompt_revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
    );
    let route = RouteRevisionReference::new(
        RouteDefinitionId::new(
            row.try_get::<String, _>("route_definition_id")
                .map_err(|_| invalid_data())?,
        )
        .map_err(|_| invalid_data())?,
        crate::DefinitionRevision::from_u64(positive_u64(
            row.try_get("route_revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
    );
    let schema = match (
        row.try_get::<Option<String>, _>("schema_definition_id")
            .map_err(|_| invalid_data())?,
        row.try_get::<Option<i64>, _>("schema_revision")
            .map_err(|_| invalid_data())?,
    ) {
        (None, None) => None,
        (Some(id), Some(revision)) => Some(SchemaRevisionReference::new(
            SchemaDefinitionId::new(id).map_err(|_| invalid_data())?,
            crate::DefinitionRevision::from_u64(positive_u64(revision)?)
                .map_err(|_| invalid_data())?,
        )),
        _ => return Err(invalid_data()),
    };
    let tools: Vec<ToolRevisionReference> = serde_json::from_value(
        row.try_get::<Value, _>("tool_references")
            .map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())?;
    DurableJobReferenceSnapshot::new(
        ConversationId::from_uuid(row.try_get("conversation_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        JobId::from_uuid(row.try_get("job_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        prompt,
        route,
        schema,
        tools,
        row.try_get("captured_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())
}

fn fence_event_from_row(row: &PgRow) -> ConversationRepositoryResult<DeletionFenceEvent> {
    let authorization = ConversationAuthorization::new(
        TenantId::from_uuid(row.try_get("tenant_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        SubjectId::from_uuid(row.try_get("principal_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
    );
    let command = FenceConversationDeletion::new(
        ConversationId::from_uuid(row.try_get("conversation_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        DeletionRequestId::from_uuid(row.try_get("request_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        ConversationRevision::from_u64(positive_u64(
            row.try_get("prior_revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
        row.try_get("fenced_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())?;
    DeletionFenceEvent::new(
        DeletionFenceEventId::from_uuid(row.try_get("event_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        authorization,
        command,
        ConversationRevision::from_u64(positive_u64(
            row.try_get("fenced_revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())
}

fn inventory_event_from_row(row: &PgRow) -> ConversationRepositoryResult<RetentionInventoryEvent> {
    let entries: Vec<RetentionInventoryEntry> = serde_json::from_value(
        row.try_get::<Value, _>("entries")
            .map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())?;
    let authorization = ConversationAuthorization::new(
        TenantId::from_uuid(row.try_get("tenant_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        SubjectId::from_uuid(row.try_get("principal_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
    );
    let command = FenceConversationDeletion::new(
        ConversationId::from_uuid(row.try_get("conversation_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        DeletionRequestId::from_uuid(row.try_get("request_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        ConversationRevision::from_u64(positive_u64(
            row.try_get("prior_revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
        row.try_get("fenced_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())?;
    let fence = DeletionFenceEvent::new(
        DeletionFenceEventId::from_uuid(row.try_get("fence_event_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        authorization,
        command,
        ConversationRevision::from_u64(positive_u64(
            row.try_get("fenced_revision").map_err(|_| invalid_data())?,
        )?)
        .map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())?;
    RetentionInventoryEvent::new(
        RetentionInventoryEventId::from_uuid(row.try_get("event_id").map_err(|_| invalid_data())?)
            .map_err(|_| invalid_data())?,
        fence,
        entries,
        row.try_get("inventoried_at").map_err(|_| invalid_data())?,
    )
    .map_err(|_| invalid_data())
}

async fn lock_conversation(
    transaction: &mut Transaction<'_, Postgres>,
    authorization: &ConversationAuthorization,
    conversation_id: ConversationId,
) -> ConversationRepositoryResult<Option<Conversation>> {
    let row = sqlx::query(
        "SELECT tenant_id, principal_id, conversation_id, revision, last_message_sequence, \
                deletion_request_id, fenced_at, created_at, updated_at \
         FROM public.llm_conversations \
         WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 FOR UPDATE",
    )
    .bind(authorization.tenant_id().as_uuid())
    .bind(authorization.principal_id().as_uuid())
    .bind(conversation_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    row.as_ref().map(conversation_from_row).transpose()
}

async fn update_conversation(
    transaction: &mut Transaction<'_, Postgres>,
    authorization: &ConversationAuthorization,
    prior_revision: ConversationRevision,
    conversation: &Conversation,
) -> ConversationRepositoryResult<()> {
    let (request_id, fenced_at) = match conversation.status() {
        ConversationStatus::Active => (None, None),
        ConversationStatus::DeletionFenced {
            request_id,
            fenced_at,
        } => (Some(request_id.as_uuid()), Some(fenced_at)),
    };
    let updated = sqlx::query(
        "UPDATE public.llm_conversations \
         SET revision = $4, last_message_sequence = $5, deletion_request_id = $6, fenced_at = $7, updated_at = $8 \
         WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND revision = $9",
    )
    .bind(authorization.tenant_id().as_uuid())
    .bind(authorization.principal_id().as_uuid())
    .bind(conversation.id().as_uuid())
    .bind(i64::try_from(conversation.revision().get()).map_err(|_| invalid_data())?)
    .bind(conversation.last_message_sequence().map(MessageSequence::get).map(i64::try_from).transpose().map_err(|_| invalid_data())?)
    .bind(request_id)
    .bind(fenced_at)
    .bind(conversation.updated_at())
    .bind(i64::try_from(prior_revision.get()).map_err(|_| invalid_data())?)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(ConversationRepositoryError::Unavailable)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "transactional repository methods keep lock, mutation, and commit in one auditably atomic scope"
)]
#[async_trait]
impl ConversationRepository for PostgresConversationRepository {
    async fn create_conversation(
        &self,
        authorization: &ConversationAuthorization,
        command: &CreateConversation,
    ) -> ConversationRepositoryResult<CreateConversationOutcome> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let inserted = sqlx::query(
            "INSERT INTO public.llm_conversations \
                (tenant_id, principal_id, conversation_id, revision, last_message_sequence, deletion_request_id, fenced_at, created_at, updated_at) \
             VALUES ($1, $2, $3, 1, NULL, NULL, NULL, $4, $4) \
             ON CONFLICT (tenant_id, principal_id, conversation_id) DO NOTHING \
             RETURNING tenant_id, principal_id, conversation_id, revision, last_message_sequence, deletion_request_id, fenced_at, created_at, updated_at",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.created_at())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if let Some(row) = inserted {
            let conversation = conversation_from_row(&row)?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(CreateConversationOutcome::Created(conversation));
        }
        let row = sqlx::query(
            "SELECT tenant_id, principal_id, conversation_id, revision, last_message_sequence, deletion_request_id, fenced_at, created_at, updated_at \
             FROM public.llm_conversations WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or_else(invalid_data)?;
        let existing = conversation_from_row(&row)?;
        let outcome = if existing.created_at() == command.created_at() {
            CreateConversationOutcome::Replayed(existing)
        } else {
            CreateConversationOutcome::IdempotencyConflict
        };
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(outcome)
    }

    async fn read_conversation(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: ConversationId,
    ) -> ConversationRepositoryResult<Option<Conversation>> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let row = sqlx::query(
            "SELECT tenant_id, principal_id, conversation_id, revision, last_message_sequence, deletion_request_id, fenced_at, created_at, updated_at \
             FROM public.llm_conversations WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(conversation_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let conversation = row.as_ref().map(conversation_from_row).transpose()?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(conversation)
    }

    async fn append_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &AppendMessage,
    ) -> ConversationRepositoryResult<AppendMessageOutcome> {
        let canonical = serde_json::to_value(command.message()).map_err(|_| invalid_data())?;
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, command.conversation_id()).await?
        else {
            return Ok(AppendMessageOutcome::NotFound);
        };
        let existing = sqlx::query(
            "SELECT conversation_id, message_id, sequence, revision, canonical_message, created_at, updated_at \
             FROM public.llm_messages WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND message_id = $4",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.message_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if let Some(row) = existing {
            let message = message_from_row(&row)?;
            return Ok(
                if message.message() == command.message()
                    && message.created_at() == command.created_at()
                {
                    AppendMessageOutcome::Replayed {
                        message,
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
            .map_err(|_| invalid_data())?;
        let row = sqlx::query(
            "INSERT INTO public.llm_messages \
                (tenant_id, principal_id, conversation_id, message_id, sequence, revision, canonical_message, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $7) \
             RETURNING conversation_id, message_id, sequence, revision, canonical_message, created_at, updated_at",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.message_id().as_uuid())
        .bind(i64::try_from(sequence.get()).map_err(|_| invalid_data())?)
        .bind(canonical)
        .bind(command.created_at())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let message = message_from_row(&row)?;
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &next,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
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
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.llm_conversations WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3)",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(request.conversation_id().as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if !exists {
            return Ok(ReadMessagesOutcome::NotFound);
        }
        let after = request
            .cursor()
            .map(crate::MessageCursor::after_sequence)
            .map(MessageSequence::get)
            .map(i64::try_from)
            .transpose()
            .map_err(|_| invalid_data())?
            .unwrap_or(0);
        let rows = sqlx::query(
            "SELECT conversation_id, message_id, sequence, revision, canonical_message, created_at, updated_at \
             FROM public.llm_messages WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND sequence > $4 \
             ORDER BY sequence ASC LIMIT $5",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(request.conversation_id().as_uuid())
        .bind(after)
        .bind(i64::from(request.limit().get()) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let has_more = rows.len() > usize::from(request.limit().get());
        let messages = rows
            .iter()
            .take(usize::from(request.limit().get()))
            .map(message_from_row)
            .collect::<ConversationRepositoryResult<Vec<_>>>()?;
        let page = MessagePage::new(request, messages, has_more).map_err(|_| invalid_data())?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(ReadMessagesOutcome::Found(page))
    }

    async fn update_message(
        &self,
        authorization: &ConversationAuthorization,
        command: &UpdateMessage,
    ) -> ConversationRepositoryResult<UpdateMessageOutcome> {
        let canonical = serde_json::to_value(command.message()).map_err(|_| invalid_data())?;
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, command.conversation_id()).await?
        else {
            return Ok(UpdateMessageOutcome::NotFound);
        };
        if conversation.is_deletion_fenced() {
            return Ok(UpdateMessageOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(UpdateMessageOutcome::VersionConflict);
        }
        let row = sqlx::query(
            "SELECT conversation_id, message_id, sequence, revision, canonical_message, created_at, updated_at \
             FROM public.llm_messages WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND message_id = $4 FOR UPDATE",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.message_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let Some(row) = row else {
            return Ok(UpdateMessageOutcome::NotFound);
        };
        let current = message_from_row(&row)?;
        if current.revision() != command.expected_message_revision() {
            return Ok(UpdateMessageOutcome::VersionConflict);
        }
        let revised = current.revise(command).map_err(|_| invalid_data())?;
        let next = conversation
            .advance(command.updated_at())
            .map_err(|_| invalid_data())?;
        let updated = sqlx::query(
            "UPDATE public.llm_messages SET revision = $5, canonical_message = $6, updated_at = $7 \
             WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND message_id = $4 AND revision = $8",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.message_id().as_uuid())
        .bind(i64::try_from(revised.revision().get()).map_err(|_| invalid_data())?)
        .bind(canonical)
        .bind(command.updated_at())
        .bind(i64::try_from(current.revision().get()).map_err(|_| invalid_data())?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if updated.rows_affected() != 1 {
            return Err(ConversationRepositoryError::Unavailable);
        }
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &next,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
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
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, command.conversation_id()).await?
        else {
            return Ok(DeleteMessageOutcome::NotFound);
        };
        if conversation.is_deletion_fenced() {
            return Ok(DeleteMessageOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(DeleteMessageOutcome::VersionConflict);
        }
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM public.llm_messages WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND message_id = $4 FOR UPDATE",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.message_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let Some(revision) = revision else {
            return Ok(DeleteMessageOutcome::NotFound);
        };
        let revision = ConversationMessageRevision::from_u64(positive_u64(revision)?)
            .map_err(|_| invalid_data())?;
        if revision != command.expected_message_revision() {
            return Ok(DeleteMessageOutcome::VersionConflict);
        }
        let next = conversation
            .advance(command.deleted_at())
            .map_err(|_| invalid_data())?;
        let deleted = sqlx::query(
            "DELETE FROM public.llm_messages WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND message_id = $4 AND revision = $5",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.message_id().as_uuid())
        .bind(i64::try_from(revision.get()).map_err(|_| invalid_data())?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if deleted.rows_affected() != 1 {
            return Err(ConversationRepositoryError::Unavailable);
        }
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &next,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(DeleteMessageOutcome::Deleted {
            conversation_revision: next.revision(),
        })
    }

    async fn save_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        command: &SaveProviderState,
    ) -> ConversationRepositoryResult<SaveProviderStateOutcome> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, command.conversation_id()).await?
        else {
            return Ok(SaveProviderStateOutcome::NotFound);
        };
        let row = sqlx::query(
            "SELECT conversation_id, state_id, revision, state_kind, reasoning_summary, reasoning_signature, encrypted_reference, \
                    encryption_key_id, encryption_key_revision, encryption_algorithm, ciphertext_digest, created_at, updated_at \
             FROM public.llm_provider_state WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND state_id = $4 FOR UPDATE",
        )
        .bind(authorization.tenant_id().as_uuid())
        .bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid())
        .bind(command.state_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let existing = row.as_ref().map(provider_state_from_row).transpose()?;
        if let Some(existing) = &existing
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
        let saved = match existing {
            Some(existing) if Some(existing.revision()) == command.expected_state_revision() => {
                existing.revise(command).map_err(|_| invalid_data())?
            }
            None if command.expected_state_revision().is_none() => {
                ProviderStateRecord::from_save(command).map_err(|_| invalid_data())?
            }
            _ => return Ok(SaveProviderStateOutcome::VersionConflict),
        };
        let next = conversation
            .advance(command.updated_at())
            .map_err(|_| invalid_data())?;
        let columns = provider_columns(saved.value());
        match command.expected_state_revision() {
            None => {
                sqlx::query(
                    "INSERT INTO public.llm_provider_state \
                        (tenant_id, principal_id, conversation_id, state_id, revision, state_kind, reasoning_summary, reasoning_signature, \
                         encrypted_reference, encryption_key_id, encryption_key_revision, encryption_algorithm, ciphertext_digest, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)",
                )
                .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
                .bind(command.conversation_id().as_uuid()).bind(command.state_id().as_uuid())
                .bind(i64::try_from(saved.revision().get()).map_err(|_| invalid_data())?)
                .bind(columns.kind).bind(columns.summary).bind(columns.signature).bind(columns.encrypted_reference)
                .bind(columns.key_id).bind(columns.key_revision).bind(columns.algorithm)
                .bind(columns.ciphertext_digest.as_ref().map(|digest| digest.as_bytes().as_slice()))
                .bind(command.updated_at()).execute(&mut *transaction).await.map_err(map_sqlx)?;
            }
            Some(expected) => {
                let updated = sqlx::query(
                    "UPDATE public.llm_provider_state SET revision = $5, state_kind = $6, reasoning_summary = $7, reasoning_signature = $8, \
                         encrypted_reference = $9, encryption_key_id = $10, encryption_key_revision = $11, encryption_algorithm = $12, \
                         ciphertext_digest = $13, updated_at = $14 \
                     WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND state_id = $4 AND revision = $15",
                )
                .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
                .bind(command.conversation_id().as_uuid()).bind(command.state_id().as_uuid())
                .bind(i64::try_from(saved.revision().get()).map_err(|_| invalid_data())?)
                .bind(columns.kind).bind(columns.summary).bind(columns.signature).bind(columns.encrypted_reference)
                .bind(columns.key_id).bind(columns.key_revision).bind(columns.algorithm)
                .bind(columns.ciphertext_digest.as_ref().map(|digest| digest.as_bytes().as_slice()))
                .bind(command.updated_at()).bind(i64::try_from(expected.get()).map_err(|_| invalid_data())?)
                .execute(&mut *transaction).await.map_err(map_sqlx)?;
                if updated.rows_affected() != 1 {
                    return Err(ConversationRepositoryError::Unavailable);
                }
            }
        }
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &next,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
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
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let row = sqlx::query(
            "SELECT conversation_id, state_id, revision, state_kind, reasoning_summary, reasoning_signature, encrypted_reference, \
                    encryption_key_id, encryption_key_revision, encryption_algorithm, ciphertext_digest, created_at, updated_at \
             FROM public.llm_provider_state WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND state_id = $4",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(conversation_id.as_uuid()).bind(state_id.as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        let state = row.as_ref().map(provider_state_from_row).transpose()?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(state)
    }

    async fn delete_provider_state(
        &self,
        authorization: &ConversationAuthorization,
        command: &DeleteProviderState,
    ) -> ConversationRepositoryResult<DeleteProviderStateOutcome> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, command.conversation_id()).await?
        else {
            return Ok(DeleteProviderStateOutcome::NotFound);
        };
        if conversation.is_deletion_fenced() {
            return Ok(DeleteProviderStateOutcome::DeletionFenced);
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(DeleteProviderStateOutcome::VersionConflict);
        }
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM public.llm_provider_state WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND state_id = $4 FOR UPDATE",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid()).bind(command.state_id().as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        let Some(revision) = revision else {
            return Ok(DeleteProviderStateOutcome::NotFound);
        };
        let revision =
            ProviderStateRevision::from_u64(positive_u64(revision)?).map_err(|_| invalid_data())?;
        if revision != command.expected_state_revision() {
            return Ok(DeleteProviderStateOutcome::VersionConflict);
        }
        let next = conversation
            .advance(command.deleted_at())
            .map_err(|_| invalid_data())?;
        let deleted = sqlx::query(
            "DELETE FROM public.llm_provider_state WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND state_id = $4 AND revision = $5",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid()).bind(command.state_id().as_uuid())
        .bind(i64::try_from(revision.get()).map_err(|_| invalid_data())?)
        .execute(&mut *transaction).await.map_err(map_sqlx)?;
        if deleted.rows_affected() != 1 {
            return Err(ConversationRepositoryError::Unavailable);
        }
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &next,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
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
        let tools = serde_json::to_value(snapshot.tools()).map_err(|_| invalid_data())?;
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, snapshot.conversation_id()).await?
        else {
            return Ok(SaveJobReferenceSnapshotOutcome::NotFound);
        };
        let row = sqlx::query(
            "SELECT conversation_id, job_id, prompt_definition_id, prompt_revision, route_definition_id, route_revision, \
                    schema_definition_id, schema_revision, tool_references, captured_at \
             FROM public.llm_job_reference_snapshots WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND job_id = $4",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(snapshot.conversation_id().as_uuid()).bind(snapshot.job_id().as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        if let Some(row) = row {
            let existing = job_snapshot_from_row(&row)?;
            return Ok(if &existing == snapshot {
                SaveJobReferenceSnapshotOutcome::Replayed {
                    snapshot: existing,
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
            .map_err(|_| invalid_data())?;
        sqlx::query(
            "INSERT INTO public.llm_job_reference_snapshots \
                (tenant_id, principal_id, conversation_id, job_id, prompt_definition_id, prompt_revision, route_definition_id, route_revision, \
                 schema_definition_id, schema_revision, tool_references, captured_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(snapshot.conversation_id().as_uuid()).bind(snapshot.job_id().as_uuid())
        .bind(snapshot.prompt().id().as_str()).bind(i64::try_from(snapshot.prompt().revision().get()).map_err(|_| invalid_data())?)
        .bind(snapshot.route().id().as_str()).bind(i64::try_from(snapshot.route().revision().get()).map_err(|_| invalid_data())?)
        .bind(snapshot.schema().map(|schema| schema.id().as_str()))
        .bind(snapshot.schema().map(|schema| i64::try_from(schema.revision().get())).transpose().map_err(|_| invalid_data())?)
        .bind(tools).bind(snapshot.captured_at())
        .execute(&mut *transaction).await.map_err(map_sqlx)?;
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &next,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
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
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let row = sqlx::query(
            "SELECT conversation_id, job_id, prompt_definition_id, prompt_revision, route_definition_id, route_revision, \
                    schema_definition_id, schema_revision, tool_references, captured_at \
             FROM public.llm_job_reference_snapshots WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND job_id = $4",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(conversation_id.as_uuid()).bind(job_id.as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        let snapshot = row.as_ref().map(job_snapshot_from_row).transpose()?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(snapshot)
    }

    async fn fence_conversation_deletion(
        &self,
        authorization: &ConversationAuthorization,
        command: FenceConversationDeletion,
    ) -> ConversationRepositoryResult<FenceConversationDeletionOutcome> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let Some(conversation) =
            lock_conversation(&mut transaction, authorization, command.conversation_id()).await?
        else {
            return Ok(FenceConversationDeletionOutcome::NotFound);
        };
        let row = sqlx::query(
            "SELECT tenant_id, principal_id, conversation_id, event_id, request_id, prior_revision, fenced_revision, fenced_at \
             FROM public.llm_deletion_fence_events WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid()).fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        if let Some(row) = row {
            let event = fence_event_from_row(&row)?;
            return Ok(if event.matches_command(command) {
                FenceConversationDeletionOutcome::Replayed {
                    conversation,
                    event,
                }
            } else if event.request_id() == command.request_id() {
                FenceConversationDeletionOutcome::IdempotencyConflict
            } else {
                FenceConversationDeletionOutcome::AlreadyFenced
            });
        }
        if conversation.is_deletion_fenced() {
            return Err(invalid_data());
        }
        if conversation.revision() != command.expected_conversation_revision() {
            return Ok(FenceConversationDeletionOutcome::VersionConflict);
        }
        let fenced = conversation
            .fence_deletion(command.request_id(), command.fenced_at())
            .map_err(|_| invalid_data())?;
        let event = DeletionFenceEvent::new(
            DeletionFenceEventId::new(),
            *authorization,
            command,
            fenced.revision(),
        )
        .map_err(|_| invalid_data())?;
        update_conversation(
            &mut transaction,
            authorization,
            conversation.revision(),
            &fenced,
        )
        .await?;
        sqlx::query(
            "INSERT INTO public.llm_deletion_fence_events \
                (tenant_id, principal_id, conversation_id, event_id, request_id, prior_revision, fenced_revision, fenced_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(command.conversation_id().as_uuid()).bind(event.event_id().as_uuid()).bind(event.request_id().as_uuid())
        .bind(i64::try_from(event.prior_revision().get()).map_err(|_| invalid_data())?)
        .bind(i64::try_from(event.fenced_revision().get()).map_err(|_| invalid_data())?)
        .bind(event.fenced_at()).execute(&mut *transaction).await.map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
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
        if event.tenant_id() != authorization.tenant_id()
            || event.principal_id() != authorization.principal_id()
        {
            return Ok(RecordRetentionInventoryOutcome::NotFound);
        }
        let entries = serde_json::to_value(event.entries()).map_err(|_| invalid_data())?;
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let fence = sqlx::query(
            "SELECT tenant_id, principal_id, conversation_id, event_id, request_id, prior_revision, fenced_revision, fenced_at \
             FROM public.llm_deletion_fence_events WHERE tenant_id = $1 AND principal_id = $2 AND conversation_id = $3 AND event_id = $4 AND request_id = $5",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(event.conversation_id().as_uuid()).bind(event.fence_event_id().as_uuid()).bind(event.request_id().as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        let Some(fence) = fence else {
            return Ok(RecordRetentionInventoryOutcome::NotFound);
        };
        if fence_event_from_row(&fence)?.fenced_at() != event.fenced_at() {
            return Ok(RecordRetentionInventoryOutcome::NotFound);
        }
        let existing = sqlx::query(
            "SELECT inventory.tenant_id, inventory.principal_id, inventory.conversation_id, inventory.event_id, inventory.fence_event_id, \
                    inventory.request_id, inventory.fenced_at, inventory.entries, inventory.inventoried_at, fence.prior_revision, fence.fenced_revision \
             FROM public.llm_retention_inventory_events AS inventory \
             JOIN public.llm_deletion_fence_events AS fence \
               ON fence.tenant_id = inventory.tenant_id AND fence.principal_id = inventory.principal_id \
              AND fence.conversation_id = inventory.conversation_id AND fence.event_id = inventory.fence_event_id AND fence.request_id = inventory.request_id \
             WHERE inventory.tenant_id = $1 AND inventory.principal_id = $2 AND inventory.conversation_id = $3 AND inventory.event_id = $4 \
               AND fence.tenant_id = $1 AND fence.principal_id = $2",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(event.conversation_id().as_uuid()).bind(event.event_id().as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        if let Some(row) = existing {
            let existing = inventory_event_from_row(&row)?;
            return Ok(if &existing == event {
                RecordRetentionInventoryOutcome::Replayed(existing)
            } else {
                RecordRetentionInventoryOutcome::IdempotencyConflict
            });
        }
        sqlx::query(
            "INSERT INTO public.llm_retention_inventory_events \
                (tenant_id, principal_id, conversation_id, event_id, fence_event_id, request_id, fenced_at, entries, inventoried_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(event.conversation_id().as_uuid()).bind(event.event_id().as_uuid()).bind(event.fence_event_id().as_uuid())
        .bind(event.request_id().as_uuid()).bind(event.fenced_at()).bind(entries).bind(event.inventoried_at())
        .execute(&mut *transaction).await.map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(RecordRetentionInventoryOutcome::Recorded(event.clone()))
    }

    async fn read_retention_inventory(
        &self,
        authorization: &ConversationAuthorization,
        conversation_id: ConversationId,
        fence_event_id: DeletionFenceEventId,
    ) -> ConversationRepositoryResult<Option<RetentionInventoryEvent>> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut transaction = connection.begin().await.map_err(map_sqlx)?;
        set_scope(&mut transaction, authorization).await?;
        let row = sqlx::query(
            "SELECT inventory.tenant_id, inventory.principal_id, inventory.conversation_id, inventory.event_id, inventory.fence_event_id, \
                    inventory.request_id, inventory.fenced_at, inventory.entries, inventory.inventoried_at, fence.prior_revision, fence.fenced_revision \
             FROM public.llm_retention_inventory_events AS inventory \
             JOIN public.llm_deletion_fence_events AS fence \
               ON fence.tenant_id = inventory.tenant_id AND fence.principal_id = inventory.principal_id \
              AND fence.conversation_id = inventory.conversation_id AND fence.event_id = inventory.fence_event_id AND fence.request_id = inventory.request_id \
             WHERE inventory.tenant_id = $1 AND inventory.principal_id = $2 AND inventory.conversation_id = $3 AND inventory.fence_event_id = $4 \
               AND fence.tenant_id = $1 AND fence.principal_id = $2 \
             ORDER BY inventory.inventoried_at DESC, inventory.event_id DESC LIMIT 1",
        )
        .bind(authorization.tenant_id().as_uuid()).bind(authorization.principal_id().as_uuid())
        .bind(conversation_id.as_uuid()).bind(fence_event_id.as_uuid())
        .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        let event = row.as_ref().map(inventory_event_from_row).transpose()?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(event)
    }
}
