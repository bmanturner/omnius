use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use async_trait::async_trait;
use omnius_postgres::PostgresPool;
use serde_json::Value;
use sqlx::{Connection as _, FromRow, PgConnection, Postgres, Row as _, Transaction, types::Json};

use crate::{
    ContentDigest, DataClassification, EvaluationSetId, OwnerId, PromptAccess, PromptBody,
    PromptCatalogStore, PromptId, PromptRevision, PromptRevisionNumber, PromptStatus,
    PromptStoreError, PromptTemplates, RouteId, ToolId,
};

/// PostgreSQL durability for atomically allocated, immutable prompt revisions.
#[derive(Clone)]
pub struct PostgresPromptCatalogStore {
    pool: PostgresPool,
}

impl PostgresPromptCatalogStore {
    /// Creates a prompt catalog store over the lifecycle-managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresPromptCatalogStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresPromptCatalogStore")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PromptCatalogStore for PostgresPromptCatalogStore {
    async fn insert_draft(
        &self,
        draft: PromptRevision,
        expected_latest: Option<PromptRevisionNumber>,
    ) -> Result<PromptRevision, PromptStoreError> {
        if draft.status() != PromptStatus::Draft
            || match expected_latest {
                Some(latest) => latest.checked_next() != Some(draft.revision()),
                None => draft.revision().get() != 1,
            }
        {
            return Err(PromptStoreError::RevisionConflict);
        }

        let revision = revision_to_i64(draft.revision())?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;

        match expected_latest {
            None => {
                let result = sqlx::query(
                    "INSERT INTO public.llm_prompts \
                     (prompt_id, latest_revision, row_version, created_at, updated_at) \
                     VALUES ($1, 1, 1, clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (prompt_id) DO NOTHING",
                )
                .bind(draft.id().as_str())
                .execute(&mut *transaction)
                .await
                .map_err(|_| PromptStoreError::Unavailable)?;
                if result.rows_affected() != 1 {
                    return Err(PromptStoreError::AlreadyExists);
                }
            }
            Some(latest) => {
                let latest = revision_to_i64(latest)?;
                let result = sqlx::query(
                    "UPDATE public.llm_prompts \
                     SET latest_revision = $3, row_version = row_version + 1, \
                         updated_at = clock_timestamp() \
                     WHERE prompt_id = $1 AND latest_revision = $2",
                )
                .bind(draft.id().as_str())
                .bind(latest)
                .bind(revision)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PromptStoreError::Unavailable)?;
                if result.rows_affected() != 1 {
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM public.llm_prompts WHERE prompt_id = $1)",
                    )
                    .bind(draft.id().as_str())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| PromptStoreError::Unavailable)?;
                    return Err(if exists {
                        PromptStoreError::RevisionConflict
                    } else {
                        PromptStoreError::NotFound
                    });
                }
            }
        }

        insert_revision(&mut transaction, &draft).await?;
        let stored = load_revision(&mut transaction, draft.id(), draft.revision()).await?;
        transaction
            .commit()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        Ok(stored)
    }

    async fn replace_draft(
        &self,
        replacement: PromptRevision,
        expected_content_digest: ContentDigest,
    ) -> Result<PromptRevision, PromptStoreError> {
        if replacement.status() != PromptStatus::Draft {
            return Err(PromptStoreError::Immutable);
        }
        let revision = revision_to_i64(replacement.revision())?;
        let body = replacement.body();
        let access = body.access();
        let replacement_digest = replacement.content_digest();
        let allowed_routes = access
            .allowed_routes()
            .iter()
            .map(RouteId::as_str)
            .collect::<Vec<_>>();
        let allowed_tools = access
            .allowed_tools()
            .iter()
            .map(ToolId::as_str)
            .collect::<Vec<_>>();
        let evaluation_sets = access
            .evaluation_sets()
            .iter()
            .map(EvaluationSetId::as_str)
            .collect::<Vec<_>>();

        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        let result = sqlx::query(
            "UPDATE public.llm_prompt_revisions SET \
             content_digest = $4, input_schema = $5, system_template = $6, \
             developer_template = $7, user_template = $8, owner_id = $9, \
             allowed_routes = $10, allowed_tools = $11, data_classification = $12, \
             evaluation_sets = $13, rollout_metadata = $14, updated_at = clock_timestamp() \
             WHERE prompt_id = $1 AND revision = $2 AND status = 'draft' \
               AND content_digest = $3",
        )
        .bind(replacement.id().as_str())
        .bind(revision)
        .bind(&expected_content_digest.as_bytes()[..])
        .bind(&replacement_digest.as_bytes()[..])
        .bind(Json(body.input_schema()))
        .bind(body.templates().system())
        .bind(body.templates().developer())
        .bind(body.templates().user())
        .bind(access.owner().as_str())
        .bind(allowed_routes)
        .bind(allowed_tools)
        .bind(classification_to_sql(access.data_classification()))
        .bind(evaluation_sets)
        .bind(Json(access.rollout_metadata()))
        .execute(&mut *transaction)
        .await
        .map_err(|_| PromptStoreError::Unavailable)?;

        if result.rows_affected() != 1 {
            let state =
                load_revision_state(&mut transaction, replacement.id(), replacement.revision())
                    .await?;
            return match state {
                None => Err(PromptStoreError::NotFound),
                Some((status, _)) if status != "draft" => Err(PromptStoreError::Immutable),
                Some((_, digest)) if digest.as_slice() != expected_content_digest.as_bytes() => {
                    Err(PromptStoreError::RevisionConflict)
                }
                Some(_) => Err(PromptStoreError::Unavailable),
            };
        }

        let stored =
            load_revision(&mut transaction, replacement.id(), replacement.revision()).await?;
        transaction
            .commit()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        Ok(stored)
    }

    async fn compare_and_set_status(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
        expected_content_digest: ContentDigest,
        expected_status: PromptStatus,
        target_status: PromptStatus,
    ) -> Result<PromptRevision, PromptStoreError> {
        if !matches!(
            (expected_status, target_status),
            (PromptStatus::Draft, PromptStatus::Published)
                | (PromptStatus::Published, PromptStatus::Deprecated)
        ) {
            return Err(PromptStoreError::RevisionConflict);
        }

        let revision_i64 = revision_to_i64(revision)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        let target = status_to_sql(target_status);
        let result = sqlx::query(
            "UPDATE public.llm_prompt_revisions SET \
             status = $5, \
             published_at = CASE WHEN $5 = 'published' THEN clock_timestamp() ELSE published_at END, \
             deprecated_at = CASE WHEN $5 = 'deprecated' THEN clock_timestamp() ELSE deprecated_at END, \
             updated_at = clock_timestamp() \
             WHERE prompt_id = $1 AND revision = $2 AND content_digest = $3 AND status = $4",
        )
        .bind(id.as_str())
        .bind(revision_i64)
        .bind(&expected_content_digest.as_bytes()[..])
        .bind(status_to_sql(expected_status))
        .bind(target)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PromptStoreError::Unavailable)?;
        if result.rows_affected() != 1 {
            return match load_revision_state(&mut transaction, id, revision).await? {
                None => Err(PromptStoreError::NotFound),
                Some(_) => Err(PromptStoreError::RevisionConflict),
            };
        }

        let stored = load_revision(&mut transaction, id, revision).await?;
        transaction
            .commit()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        Ok(stored)
    }

    async fn get_revision(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
    ) -> Result<PromptRevision, PromptStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| PromptStoreError::Unavailable)?;
        load_revision(&mut connection, id, revision).await
    }
}

async fn insert_revision(
    transaction: &mut Transaction<'_, Postgres>,
    revision: &PromptRevision,
) -> Result<(), PromptStoreError> {
    let body = revision.body();
    let content_digest = revision.content_digest();
    let access = body.access();
    let allowed_routes = access
        .allowed_routes()
        .iter()
        .map(RouteId::as_str)
        .collect::<Vec<_>>();
    let allowed_tools = access
        .allowed_tools()
        .iter()
        .map(ToolId::as_str)
        .collect::<Vec<_>>();
    let evaluation_sets = access
        .evaluation_sets()
        .iter()
        .map(EvaluationSetId::as_str)
        .collect::<Vec<_>>();
    let result = sqlx::query(
        "INSERT INTO public.llm_prompt_revisions \
         (prompt_id, revision, status, content_digest, input_schema, system_template, \
          developer_template, user_template, owner_id, allowed_routes, allowed_tools, \
          data_classification, evaluation_sets, rollout_metadata, created_at, updated_at) \
         VALUES ($1, $2, 'draft', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                 clock_timestamp(), clock_timestamp())",
    )
    .bind(revision.id().as_str())
    .bind(revision_to_i64(revision.revision())?)
    .bind(&content_digest.as_bytes()[..])
    .bind(Json(body.input_schema()))
    .bind(body.templates().system())
    .bind(body.templates().developer())
    .bind(body.templates().user())
    .bind(access.owner().as_str())
    .bind(allowed_routes)
    .bind(allowed_tools)
    .bind(classification_to_sql(access.data_classification()))
    .bind(evaluation_sets)
    .bind(Json(access.rollout_metadata()))
    .execute(&mut **transaction)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => Ok(()),
        Err(error) if is_unique_violation(&error) => Err(PromptStoreError::AlreadyExists),
        Ok(_) | Err(_) => Err(PromptStoreError::Unavailable),
    }
}

async fn load_revision(
    connection: &mut PgConnection,
    id: &PromptId,
    revision: PromptRevisionNumber,
) -> Result<PromptRevision, PromptStoreError> {
    let row = sqlx::query_as::<_, StoredPromptRevision>(
        "SELECT prompt_id, revision, status, content_digest, input_schema, system_template, \
         developer_template, user_template, owner_id, allowed_routes, allowed_tools, \
         data_classification, evaluation_sets, rollout_metadata \
         FROM public.llm_prompt_revisions WHERE prompt_id = $1 AND revision = $2",
    )
    .bind(id.as_str())
    .bind(revision_to_i64(revision)?)
    .fetch_optional(connection)
    .await
    .map_err(|_| PromptStoreError::Unavailable)?
    .ok_or(PromptStoreError::NotFound)?;
    row.decode()
}

async fn load_revision_state(
    connection: &mut PgConnection,
    id: &PromptId,
    revision: PromptRevisionNumber,
) -> Result<Option<(String, Vec<u8>)>, PromptStoreError> {
    sqlx::query(
        "SELECT status, content_digest FROM public.llm_prompt_revisions \
         WHERE prompt_id = $1 AND revision = $2",
    )
    .bind(id.as_str())
    .bind(revision_to_i64(revision)?)
    .fetch_optional(connection)
    .await
    .map_err(|_| PromptStoreError::Unavailable)?
    .map(|row| {
        Ok((
            row.try_get("status")
                .map_err(|_| PromptStoreError::Unavailable)?,
            row.try_get("content_digest")
                .map_err(|_| PromptStoreError::Unavailable)?,
        ))
    })
    .transpose()
}

#[derive(FromRow)]
struct StoredPromptRevision {
    prompt_id: String,
    revision: i64,
    status: String,
    content_digest: Vec<u8>,
    input_schema: Json<Value>,
    system_template: Option<String>,
    developer_template: Option<String>,
    user_template: String,
    owner_id: String,
    allowed_routes: Vec<String>,
    allowed_tools: Vec<String>,
    data_classification: String,
    evaluation_sets: Vec<String>,
    rollout_metadata: Json<BTreeMap<String, String>>,
}

impl StoredPromptRevision {
    fn decode(self) -> Result<PromptRevision, PromptStoreError> {
        let id = PromptId::new(self.prompt_id).map_err(|_| PromptStoreError::Unavailable)?;
        let revision = PromptRevisionNumber::new(
            u64::try_from(self.revision).map_err(|_| PromptStoreError::Unavailable)?,
        )
        .map_err(|_| PromptStoreError::Unavailable)?;
        let digest_bytes: [u8; 32] = self
            .content_digest
            .try_into()
            .map_err(|_| PromptStoreError::Unavailable)?;
        let content_digest = ContentDigest::from_bytes(digest_bytes);
        let templates = PromptTemplates::new(
            self.system_template,
            self.developer_template,
            self.user_template,
        )
        .map_err(|_| PromptStoreError::Unavailable)?;
        let access = PromptAccess::new(
            OwnerId::new(self.owner_id).map_err(|_| PromptStoreError::Unavailable)?,
            decode_ids(self.allowed_routes, RouteId::new)?,
            decode_ids(self.allowed_tools, ToolId::new)?,
            classification_from_sql(&self.data_classification)?,
            decode_ids(self.evaluation_sets, EvaluationSetId::new)?,
            self.rollout_metadata.0,
        )
        .map_err(|_| PromptStoreError::Unavailable)?;
        let body = PromptBody::new(self.input_schema.0, templates, access)
            .map_err(|_| PromptStoreError::Unavailable)?;
        PromptRevision::from_persisted(
            id,
            revision,
            status_from_sql(&self.status)?,
            body,
            content_digest,
        )
        .map_err(|_| PromptStoreError::Unavailable)
    }
}

fn decode_ids<T, E>(
    values: Vec<String>,
    constructor: impl Fn(String) -> Result<T, E>,
) -> Result<BTreeSet<T>, PromptStoreError>
where
    T: Ord,
{
    values
        .into_iter()
        .map(constructor)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| PromptStoreError::Unavailable)
}

fn revision_to_i64(revision: PromptRevisionNumber) -> Result<i64, PromptStoreError> {
    i64::try_from(revision.get()).map_err(|_| PromptStoreError::RevisionConflict)
}

const fn status_to_sql(status: PromptStatus) -> &'static str {
    match status {
        PromptStatus::Draft => "draft",
        PromptStatus::Published => "published",
        PromptStatus::Deprecated => "deprecated",
    }
}

fn status_from_sql(status: &str) -> Result<PromptStatus, PromptStoreError> {
    match status {
        "draft" => Ok(PromptStatus::Draft),
        "published" => Ok(PromptStatus::Published),
        "deprecated" => Ok(PromptStatus::Deprecated),
        _ => Err(PromptStoreError::Unavailable),
    }
}

const fn classification_to_sql(classification: DataClassification) -> &'static str {
    match classification {
        DataClassification::Public => "public",
        DataClassification::Internal => "internal",
        DataClassification::Confidential => "confidential",
        DataClassification::Restricted => "restricted",
    }
}

fn classification_from_sql(classification: &str) -> Result<DataClassification, PromptStoreError> {
    match classification {
        "public" => Ok(DataClassification::Public),
        "internal" => Ok(DataClassification::Internal),
        "confidential" => Ok(DataClassification::Confidential),
        "restricted" => Ok(DataClassification::Restricted),
        _ => Err(PromptStoreError::Unavailable),
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("23505")
    )
}
