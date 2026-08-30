use futures::future::BoxFuture;
use omnius_auth_core::{SubjectId, TenantId};
use omnius_object_storage::ObjectKey;
use omnius_postgres::{PostgresError, PostgresPool};
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    ClaimReconciliationRequest, ClaimToken, CompleteDeletionRequest, DeleteFence,
    DeleteRequestOutcome, DeletionRevision, ExpectedMedia, MediaId, MediaKind, MediaMime,
    MediaObject, MediaOrigin, MediaPolicy, MediaRejection, MediaRepository, MediaState,
    PersistedMediaObject, PublishScanRequest, ReconcileAction, ReconciliationClaim,
    ReconciliationRepositoryOutcome, ReleaseClaimRequest, RepositoryError, RequestDeletion,
    ScanCommitOutcome, ScanPublication, Sha256Digest, TransitionFence,
};

const FIND_MEDIA_QUERY: &str = "SELECT media_id, tenant_id, owner_subject_id, object_key, origin, kind, expected_size, expected_sha256, expected_mime, state, rejection_reason, expires_at, revision, deletion_revision, created_at, updated_at FROM public.llm_media_objects WHERE tenant_id = $1 AND media_id = $2";
const CLAIM_MEDIA_QUERY: &str = "SELECT media_id, tenant_id, owner_subject_id, object_key, origin, kind, expected_size, expected_sha256, expected_mime, state, rejection_reason, expires_at, revision, deletion_revision, created_at, updated_at FROM public.llm_media_objects WHERE state IN ('quarantined', 'rejected', 'deletion_pending') AND (state <> 'quarantined' OR expires_at > $1) AND (claim_token IS NULL OR claim_expires_at <= $1) ORDER BY updated_at, media_id LIMIT $2 FOR UPDATE SKIP LOCKED";
const MAX_RECONCILIATION_LEASE: time::Duration = time::Duration::minutes(5);

/// PostgreSQL-authoritative media metadata and reconciliation leases.
#[derive(Clone)]
pub struct PostgresMediaRepository {
    pool: PostgresPool,
}

impl PostgresMediaRepository {
    /// Creates a repository over the managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

impl MediaRepository for PostgresMediaRepository {
    fn insert(&self, media: MediaObject) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move {
            let fields = media.into_persisted();
            let object_key = parse_object_key_uuid(&fields.storage_key)?;
            let expected_size = encode_revision(fields.expected.size_bytes())?;
            let revision = encode_revision(fields.revision)?;
            let deletion_revision = fields
                .deletion_revision
                .map(|value| encode_revision(value.get()))
                .transpose()?;
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            sqlx::query(
                "INSERT INTO public.llm_media_objects (media_id, tenant_id, owner_subject_id, object_key, origin, kind, expected_size, expected_sha256, expected_mime, state, rejection_reason, expires_at, revision, deletion_revision, claim_token, claim_expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NULL, NULL, $15, $16)",
            )
            .bind(fields.id.as_uuid())
            .bind(fields.tenant_id.as_uuid())
            .bind(fields.owner_id.as_uuid())
            .bind(object_key)
            .bind(origin_name(fields.origin))
            .bind(kind_name(fields.kind))
            .bind(expected_size)
            .bind(fields.expected.sha256().as_bytes().as_slice())
            .bind(fields.expected.mime().as_str())
            .bind(state_name(fields.state))
            .bind(fields.rejection.map(rejection_name))
            .bind(fields.expires_at)
            .bind(revision)
            .bind(deletion_revision)
            .bind(fields.created_at)
            .bind(fields.updated_at)
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
            Ok(())
        })
    }

    fn find(
        &self,
        tenant_id: TenantId,
        media_id: MediaId,
    ) -> BoxFuture<'_, Result<Option<MediaObject>, RepositoryError>> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            let row = sqlx::query(FIND_MEDIA_QUERY)
                .bind(tenant_id.as_uuid())
                .bind(media_id.as_uuid())
                .fetch_optional(&mut *connection)
                .await
                .map_err(map_sqlx)?;
            row.as_ref().map(decode_media).transpose()
        })
    }

    fn request_deletion(
        &self,
        request: RequestDeletion,
    ) -> BoxFuture<'_, Result<DeleteRequestOutcome, RepositoryError>> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            let mut transaction = connection.begin().await.map_err(map_sqlx)?;
            let row = sqlx::query(
                "SELECT state, revision FROM public.llm_media_objects WHERE tenant_id = $1 AND media_id = $2 FOR UPDATE",
            )
            .bind(request.tenant_id.as_uuid())
            .bind(request.media_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let Some(row) = row else {
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok(DeleteRequestOutcome::Stale);
            };
            let state = decode_state(row.try_get("state").map_err(|_| RepositoryError::Corrupt)?)?;
            let revision = decode_revision(
                row.try_get("revision")
                    .map_err(|_| RepositoryError::Corrupt)?,
            )?;
            let outcome = match state {
                MediaState::Deleted => DeleteRequestOutcome::AlreadyDeleted,
                MediaState::Rejected | MediaState::DeletionPending => {
                    DeleteRequestOutcome::AlreadyScheduled
                }
                MediaState::Quarantined | MediaState::Clean
                    if revision != request.expected_revision =>
                {
                    DeleteRequestOutcome::Stale
                }
                MediaState::Quarantined | MediaState::Clean => {
                    let next = revision.checked_add(1).ok_or(RepositoryError::Corrupt)?;
                    sqlx::query(
                        "UPDATE public.llm_media_objects SET state = 'deletion_pending', rejection_reason = NULL, revision = $3, deletion_revision = $3, claim_token = NULL, claim_expires_at = NULL, updated_at = $4 WHERE tenant_id = $1 AND media_id = $2",
                    )
                    .bind(request.tenant_id.as_uuid())
                    .bind(request.media_id.as_uuid())
                    .bind(encode_revision(next)?)
                    .bind(request.now)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_sqlx)?;
                    DeleteRequestOutcome::Scheduled
                }
            };
            transaction.commit().await.map_err(map_sqlx)?;
            Ok(outcome)
        })
    }

    fn claim_reconciliation(
        &self,
        request: ClaimReconciliationRequest,
    ) -> BoxFuture<'_, Result<Vec<ReconciliationClaim>, RepositoryError>> {
        Box::pin(async move {
            if request.limit == 0
                || request.lease_until <= request.now
                || request.lease_until - request.now > MAX_RECONCILIATION_LEASE
            {
                return Err(RepositoryError::Conflict);
            }
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            let mut transaction = connection.begin().await.map_err(map_sqlx)?;
            sqlx::query(
                "WITH expired AS (SELECT tenant_id, media_id FROM public.llm_media_objects WHERE state IN ('quarantined', 'clean') AND expires_at <= $1 ORDER BY expires_at, media_id LIMIT $2 FOR UPDATE SKIP LOCKED) UPDATE public.llm_media_objects AS media SET state = 'deletion_pending', rejection_reason = NULL, revision = media.revision + 1, deletion_revision = media.revision + 1, claim_token = NULL, claim_expires_at = NULL, updated_at = $1 FROM expired WHERE media.tenant_id = expired.tenant_id AND media.media_id = expired.media_id",
            )
            .bind(request.now)
            .bind(i64::from(request.limit))
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;

            let rows = sqlx::query(CLAIM_MEDIA_QUERY)
                .bind(request.now)
                .bind(i64::from(request.limit))
                .fetch_all(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
            let mut claims = Vec::with_capacity(rows.len());
            for row in rows {
                let media = decode_media(&row)?;
                let token = ClaimToken::new();
                let updated = sqlx::query(
                    "UPDATE public.llm_media_objects SET claim_token = $4, claim_expires_at = $5 WHERE tenant_id = $1 AND media_id = $2 AND revision = $3",
                )
                .bind(media.tenant_id().as_uuid())
                .bind(media.id().as_uuid())
                .bind(encode_revision(media.revision())?)
                .bind(token.as_uuid())
                .bind(request.lease_until)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                if updated.rows_affected() != 1 {
                    return Err(RepositoryError::Conflict);
                }
                let action = match media.state() {
                    MediaState::Quarantined => ReconcileAction::Scan,
                    MediaState::Rejected | MediaState::DeletionPending => {
                        ReconcileAction::Delete(DeleteFence {
                            deletion_revision: media
                                .deletion_revision()
                                .ok_or(RepositoryError::Corrupt)?,
                        })
                    }
                    MediaState::Clean | MediaState::Deleted => {
                        return Err(RepositoryError::Corrupt);
                    }
                };
                claims.push(ReconciliationClaim {
                    transition: TransitionFence {
                        expected_revision: media.revision(),
                        claim_token: token,
                    },
                    media,
                    action,
                });
            }
            transaction.commit().await.map_err(map_sqlx)?;
            Ok(claims)
        })
    }

    fn publish_scan(
        &self,
        request: PublishScanRequest,
    ) -> BoxFuture<'_, Result<ScanCommitOutcome, RepositoryError>> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            let mut transaction = connection.begin().await.map_err(map_sqlx)?;
            let row = sqlx::query(
                "SELECT state, rejection_reason, expires_at, revision, claim_token, claim_expires_at FROM public.llm_media_objects WHERE tenant_id = $1 AND media_id = $2 FOR UPDATE",
            )
            .bind(request.tenant_id.as_uuid())
            .bind(request.media_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let Some(row) = row else {
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok(ScanCommitOutcome::Stale);
            };
            let state = decode_state(row.try_get("state").map_err(|_| RepositoryError::Corrupt)?)?;
            let revision = decode_revision(
                row.try_get("revision")
                    .map_err(|_| RepositoryError::Corrupt)?,
            )?;
            let expires_at: OffsetDateTime = row
                .try_get("expires_at")
                .map_err(|_| RepositoryError::Corrupt)?;
            let claim_token: Option<Uuid> = row
                .try_get("claim_token")
                .map_err(|_| RepositoryError::Corrupt)?;
            let claim_expires_at: Option<OffsetDateTime> = row
                .try_get("claim_expires_at")
                .map_err(|_| RepositoryError::Corrupt)?;
            if state != MediaState::Quarantined
                || revision != request.expected_revision
                || claim_token != Some(request.claim_token.as_uuid())
                || claim_expires_at.is_none_or(|expires_at| request.observed_at >= expires_at)
            {
                let rejection: Option<String> = row
                    .try_get("rejection_reason")
                    .map_err(|_| RepositoryError::Corrupt)?;
                let idempotent = revision == request.expected_revision.saturating_add(1)
                    && claim_token.is_none()
                    && publication_matches_state(request.publication, state, rejection.as_deref());
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok(if idempotent {
                    ScanCommitOutcome::AlreadyApplied
                } else {
                    ScanCommitOutcome::Stale
                });
            }

            let next = revision.checked_add(1).ok_or(RepositoryError::Corrupt)?;
            let outcome = if request.observed_at >= expires_at {
                sqlx::query(
                    "UPDATE public.llm_media_objects SET state = 'deletion_pending', rejection_reason = NULL, revision = $3, deletion_revision = $3, claim_token = NULL, claim_expires_at = NULL, updated_at = $4 WHERE tenant_id = $1 AND media_id = $2",
                )
                .bind(request.tenant_id.as_uuid())
                .bind(request.media_id.as_uuid())
                .bind(encode_revision(next)?)
                .bind(request.observed_at)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                ScanCommitOutcome::Expired
            } else {
                match request.publication {
                    ScanPublication::Clean => {
                        sqlx::query(
                            "UPDATE public.llm_media_objects SET state = 'clean', revision = $3, claim_token = NULL, claim_expires_at = NULL, updated_at = $4 WHERE tenant_id = $1 AND media_id = $2",
                        )
                        .bind(request.tenant_id.as_uuid())
                        .bind(request.media_id.as_uuid())
                        .bind(encode_revision(next)?)
                        .bind(request.observed_at)
                        .execute(&mut *transaction)
                        .await
                        .map_err(map_sqlx)?;
                        ScanCommitOutcome::PublishedClean
                    }
                    ScanPublication::Rejected(rejection) => {
                        sqlx::query(
                            "UPDATE public.llm_media_objects SET state = 'rejected', rejection_reason = $3, revision = $4, deletion_revision = $4, claim_token = NULL, claim_expires_at = NULL, updated_at = $5 WHERE tenant_id = $1 AND media_id = $2",
                        )
                        .bind(request.tenant_id.as_uuid())
                        .bind(request.media_id.as_uuid())
                        .bind(rejection_name(rejection))
                        .bind(encode_revision(next)?)
                        .bind(request.observed_at)
                        .execute(&mut *transaction)
                        .await
                        .map_err(map_sqlx)?;
                        ScanCommitOutcome::PublishedRejected
                    }
                }
            };
            transaction.commit().await.map_err(map_sqlx)?;
            Ok(outcome)
        })
    }

    fn complete_deletion(
        &self,
        request: CompleteDeletionRequest,
    ) -> BoxFuture<'_, Result<ReconciliationRepositoryOutcome, RepositoryError>> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            let mut transaction = connection.begin().await.map_err(map_sqlx)?;
            let row = sqlx::query(
                "SELECT state, revision, deletion_revision, claim_token, claim_expires_at FROM public.llm_media_objects WHERE tenant_id = $1 AND media_id = $2 FOR UPDATE",
            )
            .bind(request.tenant_id.as_uuid())
            .bind(request.media_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let Some(row) = row else {
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok(ReconciliationRepositoryOutcome::Stale);
            };
            let state = decode_state(row.try_get("state").map_err(|_| RepositoryError::Corrupt)?)?;
            let revision = decode_revision(
                row.try_get("revision")
                    .map_err(|_| RepositoryError::Corrupt)?,
            )?;
            let stored_deletion = row
                .try_get::<Option<i64>, _>("deletion_revision")
                .map_err(|_| RepositoryError::Corrupt)?
                .map(decode_deletion_revision)
                .transpose()?;
            let claim_token: Option<Uuid> = row
                .try_get("claim_token")
                .map_err(|_| RepositoryError::Corrupt)?;
            let claim_expires_at: Option<OffsetDateTime> = row
                .try_get("claim_expires_at")
                .map_err(|_| RepositoryError::Corrupt)?;
            if state == MediaState::Deleted && stored_deletion == Some(request.deletion_revision) {
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok(ReconciliationRepositoryOutcome::AlreadyApplied);
            }
            if !matches!(state, MediaState::Rejected | MediaState::DeletionPending)
                || revision != request.expected_revision
                || stored_deletion != Some(request.deletion_revision)
                || claim_token != Some(request.claim_token.as_uuid())
                || claim_expires_at.is_none_or(|expires_at| request.observed_at >= expires_at)
            {
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok(ReconciliationRepositoryOutcome::Stale);
            }
            let next = revision.checked_add(1).ok_or(RepositoryError::Corrupt)?;
            sqlx::query(
                "UPDATE public.llm_media_objects SET state = 'deleted', revision = $3, claim_token = NULL, claim_expires_at = NULL, updated_at = $4 WHERE tenant_id = $1 AND media_id = $2",
            )
            .bind(request.tenant_id.as_uuid())
            .bind(request.media_id.as_uuid())
            .bind(encode_revision(next)?)
            .bind(request.observed_at)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            transaction.commit().await.map_err(map_sqlx)?;
            Ok(ReconciliationRepositoryOutcome::Applied)
        })
    }

    fn release_claim(
        &self,
        request: ReleaseClaimRequest,
    ) -> BoxFuture<'_, Result<ReconciliationRepositoryOutcome, RepositoryError>> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await.map_err(map_pool)?;
            let updated = sqlx::query(
                "UPDATE public.llm_media_objects SET claim_token = NULL, claim_expires_at = NULL WHERE tenant_id = $1 AND media_id = $2 AND revision = $3 AND claim_token = $4",
            )
            .bind(request.tenant_id.as_uuid())
            .bind(request.media_id.as_uuid())
            .bind(encode_revision(request.expected_revision)?)
            .bind(request.claim_token.as_uuid())
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
            Ok(if updated.rows_affected() == 1 {
                ReconciliationRepositoryOutcome::Applied
            } else {
                ReconciliationRepositoryOutcome::Stale
            })
        })
    }
}

fn decode_media(row: &sqlx::postgres::PgRow) -> Result<MediaObject, RepositoryError> {
    let id = MediaId::from_uuid(
        row.try_get("media_id")
            .map_err(|_| RepositoryError::Corrupt)?,
    )
    .map_err(|_| RepositoryError::Corrupt)?;
    let tenant_id = TenantId::from_uuid(
        row.try_get("tenant_id")
            .map_err(|_| RepositoryError::Corrupt)?,
    )
    .map_err(|_| RepositoryError::Corrupt)?;
    let owner_id = SubjectId::from_uuid(
        row.try_get("owner_subject_id")
            .map_err(|_| RepositoryError::Corrupt)?,
    )
    .map_err(|_| RepositoryError::Corrupt)?;
    let object_key_uuid: Uuid = row
        .try_get("object_key")
        .map_err(|_| RepositoryError::Corrupt)?;
    let storage_key = ObjectKey::parse(object_key_uuid.hyphenated().to_string())
        .map_err(|_| RepositoryError::Corrupt)?;
    let expected_size = decode_revision(
        row.try_get("expected_size")
            .map_err(|_| RepositoryError::Corrupt)?,
    )?;
    let checksum: Vec<u8> = row
        .try_get("expected_sha256")
        .map_err(|_| RepositoryError::Corrupt)?;
    let checksum: [u8; 32] = checksum.try_into().map_err(|_| RepositoryError::Corrupt)?;
    let mime = MediaMime::parse(
        row.try_get::<String, _>("expected_mime")
            .map_err(|_| RepositoryError::Corrupt)?,
    )
    .map_err(|_| RepositoryError::Corrupt)?;
    let expected = ExpectedMedia::new(
        expected_size,
        Sha256Digest::from_bytes(checksum),
        mime,
        &MediaPolicy::default(),
    )
    .map_err(|_| RepositoryError::Corrupt)?;
    let rejection = row
        .try_get::<Option<String>, _>("rejection_reason")
        .map_err(|_| RepositoryError::Corrupt)?
        .as_deref()
        .map(decode_rejection)
        .transpose()?;
    let deletion_revision = row
        .try_get::<Option<i64>, _>("deletion_revision")
        .map_err(|_| RepositoryError::Corrupt)?
        .map(decode_deletion_revision)
        .transpose()?;
    MediaObject::restore(PersistedMediaObject {
        id,
        tenant_id,
        owner_id,
        storage_key,
        origin: decode_origin(
            row.try_get("origin")
                .map_err(|_| RepositoryError::Corrupt)?,
        )?,
        kind: decode_kind(row.try_get("kind").map_err(|_| RepositoryError::Corrupt)?)?,
        expected,
        state: decode_state(row.try_get("state").map_err(|_| RepositoryError::Corrupt)?)?,
        rejection,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| RepositoryError::Corrupt)?,
        revision: decode_revision(
            row.try_get("revision")
                .map_err(|_| RepositoryError::Corrupt)?,
        )?,
        deletion_revision,
        created_at: row
            .try_get("created_at")
            .map_err(|_| RepositoryError::Corrupt)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| RepositoryError::Corrupt)?,
    })
    .map_err(|_| RepositoryError::Corrupt)
}

fn publication_matches_state(
    publication: ScanPublication,
    state: MediaState,
    rejection: Option<&str>,
) -> bool {
    match publication {
        ScanPublication::Clean => state == MediaState::Clean,
        ScanPublication::Rejected(expected) => {
            state == MediaState::Rejected && rejection == Some(rejection_name(expected))
        }
    }
}

fn parse_object_key_uuid(key: &ObjectKey) -> Result<Uuid, RepositoryError> {
    Uuid::parse_str(key.as_str()).map_err(|_| RepositoryError::Corrupt)
}

fn encode_revision(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::Corrupt)
}

fn decode_revision(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::Corrupt)
}

fn decode_deletion_revision(value: i64) -> Result<DeletionRevision, RepositoryError> {
    DeletionRevision::new(decode_revision(value)?).map_err(|_| RepositoryError::Corrupt)
}

const fn origin_name(value: MediaOrigin) -> &'static str {
    match value {
        MediaOrigin::UserUpload => "user_upload",
        MediaOrigin::ProviderOutput => "provider_output",
    }
}

fn decode_origin(value: &str) -> Result<MediaOrigin, RepositoryError> {
    match value {
        "user_upload" => Ok(MediaOrigin::UserUpload),
        "provider_output" => Ok(MediaOrigin::ProviderOutput),
        _ => Err(RepositoryError::Corrupt),
    }
}

const fn kind_name(value: MediaKind) -> &'static str {
    match value {
        MediaKind::Image => "image",
        MediaKind::Audio => "audio",
        MediaKind::Video => "video",
        MediaKind::File => "file",
    }
}

fn decode_kind(value: &str) -> Result<MediaKind, RepositoryError> {
    match value {
        "image" => Ok(MediaKind::Image),
        "audio" => Ok(MediaKind::Audio),
        "video" => Ok(MediaKind::Video),
        "file" => Ok(MediaKind::File),
        _ => Err(RepositoryError::Corrupt),
    }
}

const fn state_name(value: MediaState) -> &'static str {
    match value {
        MediaState::Quarantined => "quarantined",
        MediaState::Clean => "clean",
        MediaState::Rejected => "rejected",
        MediaState::DeletionPending => "deletion_pending",
        MediaState::Deleted => "deleted",
    }
}

fn decode_state(value: &str) -> Result<MediaState, RepositoryError> {
    match value {
        "quarantined" => Ok(MediaState::Quarantined),
        "clean" => Ok(MediaState::Clean),
        "rejected" => Ok(MediaState::Rejected),
        "deletion_pending" => Ok(MediaState::DeletionPending),
        "deleted" => Ok(MediaState::Deleted),
        _ => Err(RepositoryError::Corrupt),
    }
}

const fn rejection_name(value: MediaRejection) -> &'static str {
    match value {
        MediaRejection::MissingObject => "missing_object",
        MediaRejection::SizeMismatch => "size_mismatch",
        MediaRejection::ChecksumMismatch => "checksum_mismatch",
        MediaRejection::MimeMismatch => "mime_mismatch",
        MediaRejection::ScanRejected => "scan_rejected",
        MediaRejection::ScannerFailure => "scanner_failure",
        MediaRejection::StorageFailure => "storage_failure",
    }
}

fn decode_rejection(value: &str) -> Result<MediaRejection, RepositoryError> {
    match value {
        "missing_object" => Ok(MediaRejection::MissingObject),
        "size_mismatch" => Ok(MediaRejection::SizeMismatch),
        "checksum_mismatch" => Ok(MediaRejection::ChecksumMismatch),
        "mime_mismatch" => Ok(MediaRejection::MimeMismatch),
        "scan_rejected" => Ok(MediaRejection::ScanRejected),
        "scanner_failure" => Ok(MediaRejection::ScannerFailure),
        "storage_failure" => Ok(MediaRejection::StorageFailure),
        _ => Err(RepositoryError::Corrupt),
    }
}

fn map_pool(_error: PostgresError) -> RepositoryError {
    RepositoryError::Unavailable
}

fn map_sqlx(error: sqlx::Error) -> RepositoryError {
    let mapped = if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
    {
        RepositoryError::Conflict
    } else {
        RepositoryError::Unavailable
    };
    drop(error);
    mapped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_vocabulary_rejects_unknown_state() {
        assert_eq!(decode_state("available"), Err(RepositoryError::Corrupt));
    }

    #[test]
    fn persisted_deletion_revision_rejects_zero() {
        assert_eq!(decode_deletion_revision(0), Err(RepositoryError::Corrupt));
    }

    #[test]
    fn persisted_rejection_vocabulary_round_trips() -> Result<(), RepositoryError> {
        for rejection in [
            MediaRejection::MissingObject,
            MediaRejection::SizeMismatch,
            MediaRejection::ChecksumMismatch,
            MediaRejection::MimeMismatch,
            MediaRejection::ScanRejected,
            MediaRejection::ScannerFailure,
            MediaRejection::StorageFailure,
        ] {
            assert_eq!(decode_rejection(rejection_name(rejection))?, rejection);
        }
        Ok(())
    }
}
