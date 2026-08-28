use std::{
    str::FromStr as _,
    time::{Duration, Instant},
};

use metrics::{counter, histogram};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_object_storage::ObjectKey;
use omnius_postgres::PostgresPool;
use sqlx::{Connection as _, Postgres, Row as _, Transaction, postgres::PgRow};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    DeclaredMime, LeaseToken, LeasedWork, NormalizedFilename, ReconcilerConfig, RejectionReason,
    Sha256Digest, Upload, UploadError, UploadId, UploadState, WorkFailureCode, WorkId, WorkKind,
    types::postgres_interval_micros,
};

#[derive(Clone)]
pub(crate) struct UploadDraft {
    pub id: UploadId,
    pub tenant_id: TenantId,
    pub owner_id: SubjectId,
    pub object_key: ObjectKey,
    pub published_object_key: ObjectKey,
    pub filename: NormalizedFilename,
    pub declared_size: u64,
    pub expected_sha256: Sha256Digest,
    pub declared_mime: DeclaredMime,
    pub pending_ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostWriteDisposition {
    SafeToAcknowledge,
    DeleteScheduled,
}

/// Value-free reconciliation backlog status suitable for readiness and health reporting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UploadHealth {
    /// Work immediately eligible for a claim.
    pub ready: u64,
    /// Work delayed by backoff or dormant pending upload completion.
    pub delayed: u64,
    /// Work currently protected by a live lease.
    pub leased: u64,
    /// Work that exhausted its bounded attempt budget.
    pub exhausted: u64,
}

impl UploadHealth {
    /// Returns true when no work item has exhausted its retry budget.
    #[must_use]
    pub const fn healthy(self) -> bool {
        self.exhausted == 0
    }
}

/// PostgreSQL-authoritative upload state and reconciliation ledger.
#[derive(Clone)]
pub struct PostgresUploadRepository {
    pool: PostgresPool,
}

impl PostgresUploadRepository {
    /// Creates a repository over the shared managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
    /// Resolves two opaque, pre-hashed external retry identities to one tenant-scoped upload ID.
    ///
    /// Either identity may be retried only with the same tenant, owner, and counterpart identity.
    /// The claim is durable even when the caller disconnects before upload initiation, allowing a
    /// controlled retry to recover the same `UUIDv7` without trusting a global record.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Conflict`] when either identity was previously paired differently,
    /// or [`UploadError::Database`] when the claim cannot be persisted.
    pub async fn resolve_external_identity(
        &self,
        tenant_id: TenantId,
        owner_id: SubjectId,
        workflow_key_hash: [u8; 32],
        idempotency_key_hash: [u8; 32],
    ) -> Result<UploadId, UploadError> {
        let candidate = UploadId::new();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        sqlx::query(
            "INSERT INTO upload_external_identities (
                organization_id, owner_id, workflow_key_hash, idempotency_key_hash,
                upload_id, created_at
             ) VALUES ($1, $2, $3, $4, $5, clock_timestamp())
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id.as_uuid())
        .bind(owner_id.as_uuid())
        .bind(workflow_key_hash.as_slice())
        .bind(idempotency_key_hash.as_slice())
        .bind(candidate.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        let rows = sqlx::query(
            "SELECT owner_id, workflow_key_hash, idempotency_key_hash, upload_id
             FROM upload_external_identities
             WHERE organization_id = $1
               AND (workflow_key_hash = $2 OR idempotency_key_hash = $3)
             FOR UPDATE",
        )
        .bind(tenant_id.as_uuid())
        .bind(workflow_key_hash.as_slice())
        .bind(idempotency_key_hash.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        let [row] = rows.as_slice() else {
            return Err(UploadError::Conflict);
        };
        let persisted_owner: Uuid = row.try_get("owner_id").map_err(|_| UploadError::Database)?;
        let persisted_workflow: Vec<u8> = row
            .try_get("workflow_key_hash")
            .map_err(|_| UploadError::Database)?;
        let persisted_idempotency: Vec<u8> = row
            .try_get("idempotency_key_hash")
            .map_err(|_| UploadError::Database)?;
        if persisted_owner != owner_id.as_uuid()
            || persisted_workflow.as_slice() != workflow_key_hash
            || persisted_idempotency.as_slice() != idempotency_key_hash
        {
            return Err(UploadError::Conflict);
        }
        let upload_id = UploadId::from_uuid(
            row.try_get("upload_id")
                .map_err(|_| UploadError::Database)?,
        )?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        Ok(upload_id)
    }
    /// Verifies that an existing external retry identity belongs to the exact tenant, owner, and
    /// upload without creating a new claim.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::NotFound`] when the upload has no identity claim,
    /// [`UploadError::Conflict`] when the claim belongs to different inputs, or
    /// [`UploadError::Database`] when the claim cannot be read.
    pub async fn verify_external_identity(
        &self,
        tenant_id: TenantId,
        owner_id: SubjectId,
        upload_id: UploadId,
        workflow_key_hash: [u8; 32],
        idempotency_key_hash: [u8; 32],
    ) -> Result<(), UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let row = sqlx::query(
            "SELECT owner_id, workflow_key_hash, idempotency_key_hash
             FROM upload_external_identities
             WHERE organization_id = $1 AND upload_id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(upload_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)?
        .ok_or(UploadError::NotFound)?;
        let persisted_owner: Uuid = row.try_get("owner_id").map_err(|_| UploadError::Database)?;
        let persisted_workflow: Vec<u8> = row
            .try_get("workflow_key_hash")
            .map_err(|_| UploadError::Database)?;
        let persisted_idempotency: Vec<u8> = row
            .try_get("idempotency_key_hash")
            .map_err(|_| UploadError::Database)?;
        if persisted_owner == owner_id.as_uuid()
            && persisted_workflow.as_slice() == workflow_key_hash
            && persisted_idempotency.as_slice() == idempotency_key_hash
        {
            Ok(())
        } else {
            Err(UploadError::Conflict)
        }
    }

    /// Inserts immutable upload identity and dormant verification intent in one transaction.
    /// Reusing an upload ID is idempotent only when every caller-controlled identity field matches;
    /// the original server-generated staging and publication keys are always retained. A live retry
    /// may extend the PostgreSQL-clock pending deadline, but an elapsed deadline is terminal.
    pub(crate) async fn initiate(&self, draft: &UploadDraft) -> Result<Upload, UploadError> {
        let pending_micros = postgres_interval_micros(draft.pending_ttl)?;
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let inserted = sqlx::query(
            "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
             INSERT INTO uploads (
                id, organization_id, owner_id, object_key, published_object_key, filename,
                declared_size, expected_sha256, declared_mime, state, pending_expires_at,
                created_at, updated_at
             )
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending_upload',
                    snapshot.now + $10::bigint * INTERVAL '1 microsecond',
                    snapshot.now, snapshot.now
             FROM snapshot
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(draft.id.as_uuid())
        .bind(draft.tenant_id.as_uuid())
        .bind(draft.owner_id.as_uuid())
        .bind(object_key_uuid(&draft.object_key)?)
        .bind(object_key_uuid(&draft.published_object_key)?)
        .bind(draft.filename.as_str())
        .bind(i64::try_from(draft.declared_size).map_err(|_| UploadError::Invalid)?)
        .bind(draft.expected_sha256.as_bytes().to_vec())
        .bind(draft.declared_mime.as_str())
        .bind(pending_micros)
        .execute(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?
        .rows_affected()
            == 1;

        let upload =
            load_or_extend_pending_upload(&mut transaction, draft, pending_micros, inserted)
                .await?;
        ensure_dormant_verify_work(&mut transaction, &upload).await?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        record_repository("initiate", "ok", started.elapsed());
        counter!("omnius_upload_initiated_total").increment(1);
        Ok(upload)
    }

    /// Extends the direct-credential and pending deadlines monotonically under the pending-state
    /// lock. `false` means completion or expiry won the race, so credentials must not be returned.
    pub(crate) async fn persist_direct_credential_expiry(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
        credential_lifetime: Duration,
        pending_ttl: Duration,
    ) -> Result<bool, UploadError> {
        if credential_lifetime.is_zero()
            || pending_ttl < credential_lifetime
            || pending_ttl > Duration::from_hours(24)
        {
            return Err(UploadError::Invalid);
        }
        let credential_micros = postgres_interval_micros(credential_lifetime)?;
        let pending_micros = postgres_interval_micros(pending_ttl)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let changed = sqlx::query(
            "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
             UPDATE uploads
             SET direct_credential_expires_at = GREATEST(
                    COALESCE(direct_credential_expires_at, snapshot.now),
                    snapshot.now + $3::bigint * INTERVAL '1 microsecond'
                 ),
                 pending_expires_at = GREATEST(
                    pending_expires_at,
                    snapshot.now + $4::bigint * INTERVAL '1 microsecond'
                 ),
                 updated_at = snapshot.now,
                 revision = revision + 1
             FROM snapshot
             WHERE id = $1 AND organization_id = $2 AND state = 'pending_upload'
               AND pending_expires_at > snapshot.now",
        )
        .bind(upload_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(credential_micros)
        .bind(pending_micros)
        .execute(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Looks up one upload inside exactly one tenant namespace.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::NotFound`] when the upload is absent or [`UploadError::Database`] when
    /// persistence or row decoding fails.
    pub async fn lookup(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
    ) -> Result<Upload, UploadError> {
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let result = sqlx::query("SELECT * FROM uploads WHERE id = $1 AND organization_id = $2")
            .bind(upload_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| UploadError::Database)?
            .ok_or(UploadError::NotFound)
            .and_then(|row| decode_upload(&row));
        record_repository("lookup", result_label(&result), started.elapsed());
        result
    }
    /// Looks up one upload and atomically materializes an elapsed pending deadline as rejection.
    ///
    /// # Errors
    ///
    /// Returns a tenant-scoped not-found or persistence error.
    pub(crate) async fn lookup_current(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
    ) -> Result<Upload, UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let row = sqlx::query(
            "SELECT *, pending_expires_at <= clock_timestamp() AS pending_expired
             FROM uploads WHERE id = $1 AND organization_id = $2 FOR UPDATE",
        )
        .bind(upload_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?
        .ok_or(UploadError::NotFound)?;
        let mut upload = decode_upload(&row)?;
        let pending_expired: bool = row
            .try_get("pending_expired")
            .map_err(|_| UploadError::Database)?;
        if upload.state == UploadState::PendingUpload && pending_expired {
            reject_expired_pending_locked(&mut transaction, &upload).await?;
            upload = fetch_upload_locked(&mut transaction, tenant_id, upload_id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        Ok(upload)
    }

    /// Checks pending eligibility against the PostgreSQL clock after caller authorization.
    pub(crate) async fn pending_is_live(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
    ) -> Result<bool, UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                SELECT 1 FROM uploads
                WHERE id = $1 AND organization_id = $2 AND state = 'pending_upload'
                  AND pending_expires_at > clock_timestamp()
             )",
        )
        .bind(upload_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)
    }

    /// Fences a completed proxied staging write against the authoritative upload state.
    ///
    /// A live pending row and quarantine are safe to acknowledge because every proxied overwrite is
    /// constrained to the upload's immutable length and digest. Availability is also safe because
    /// downloads use the isolated publication key, but a fresh staging cleanup is persisted. If
    /// expiry, rejection, or deletion won the race, this transaction leaves a fresh unfinished
    /// referenced delete intent before the caller can observe the state-safe outcome.
    pub(crate) async fn fence_proxied_write(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
    ) -> Result<PostWriteDisposition, UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let row = sqlx::query(
            "SELECT *, pending_expires_at <= clock_timestamp() AS pending_expired
             FROM uploads WHERE id = $1 AND organization_id = $2 FOR UPDATE",
        )
        .bind(upload_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?
        .ok_or(UploadError::NotFound)?;
        let upload = decode_upload(&row)?;
        let disposition = match upload.state {
            UploadState::PendingUpload => {
                let pending_expired: bool = row
                    .try_get("pending_expired")
                    .map_err(|_| UploadError::Database)?;
                if pending_expired {
                    reject_expired_pending_locked(&mut transaction, &upload).await?;
                    PostWriteDisposition::DeleteScheduled
                } else {
                    PostWriteDisposition::SafeToAcknowledge
                }
            }
            UploadState::Quarantined => PostWriteDisposition::SafeToAcknowledge,
            UploadState::Available => {
                ensure_orphan_delete_work_locked(
                    &mut transaction,
                    upload.tenant_id,
                    &upload.object_key,
                )
                .await?;
                PostWriteDisposition::SafeToAcknowledge
            }
            UploadState::Rejected | UploadState::Deleted => {
                ensure_referenced_delete_work_locked(&mut transaction, &upload).await?;
                PostWriteDisposition::DeleteScheduled
            }
        };
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        Ok(disposition)
    }

    /// Idempotently moves a live pending upload into quarantine and activates its verification
    /// intent no earlier than the latest persisted direct-credential expiry. An elapsed pending
    /// deadline instead fails closed and atomically schedules deletion.
    pub(crate) async fn activate_verification(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
    ) -> Result<Upload, UploadError> {
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let row = sqlx::query(
            "SELECT *, pending_expires_at <= clock_timestamp() AS pending_expired
             FROM uploads WHERE id = $1 AND organization_id = $2 FOR UPDATE",
        )
        .bind(upload_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?
        .ok_or(UploadError::NotFound)?;
        let mut upload = decode_upload(&row)?;
        if upload.state == UploadState::PendingUpload {
            let pending_expired: bool = row
                .try_get("pending_expired")
                .map_err(|_| UploadError::Database)?;
            if pending_expired {
                reject_expired_pending_locked(&mut transaction, &upload).await?;
            } else {
                sqlx::query(
                    "UPDATE uploads
                     SET state = 'quarantined', updated_at = clock_timestamp(),
                         revision = revision + 1
                     WHERE id = $1 AND organization_id = $2 AND state = 'pending_upload'",
                )
                .bind(upload_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(|_| UploadError::Database)?;
            }
            upload = fetch_upload_locked(&mut transaction, tenant_id, upload_id).await?;
        }
        if upload.state == UploadState::Quarantined {
            sqlx::query(
                "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
                 UPDATE upload_reconciliation AS work
                 SET available_at = GREATEST(
                        snapshot.now,
                        COALESCE(upload.direct_credential_expires_at, snapshot.now),
                        COALESCE(work.available_at, snapshot.now)
                     ),
                     updated_at = snapshot.now
                 FROM uploads AS upload, snapshot
                 WHERE work.upload_id = $1 AND work.organization_id = $2
                   AND work.kind = 'verify' AND work.completed_at IS NULL
                   AND upload.id = work.upload_id
                   AND upload.organization_id = work.organization_id
                   AND upload.object_key = work.object_key
                   AND upload.state = 'quarantined'",
            )
            .bind(upload_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        record_repository("complete", "ok", started.elapsed());
        Ok(upload)
    }

    /// Rejects a pending upload and atomically schedules idempotent object deletion.
    pub(crate) async fn reject_pending(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
        reason: RejectionReason,
    ) -> Result<Upload, UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let row = sqlx::query(
            "UPDATE uploads
             SET state = 'rejected', rejection_reason = $3, completed_at = clock_timestamp(),
                 updated_at = clock_timestamp(), revision = revision + 1
             WHERE id = $1 AND organization_id = $2 AND state = 'pending_upload'
             RETURNING *",
        )
        .bind(upload_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(reason.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        let upload = if let Some(row) = row {
            decode_upload(&row)?
        } else {
            let row = sqlx::query("SELECT * FROM uploads WHERE id = $1 AND organization_id = $2")
                .bind(upload_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| UploadError::Database)?
                .ok_or(UploadError::NotFound)?;
            decode_upload(&row)?
        };
        if upload.state == UploadState::Rejected {
            insert_work(
                &mut transaction,
                Some(upload.id),
                upload.tenant_id,
                &upload.object_key,
                WorkKind::Delete,
                true,
            )
            .await?;
            sqlx::query(
                "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
                 UPDATE upload_reconciliation AS work
                 SET available_at = GREATEST(
                        COALESCE(work.available_at, snapshot.now),
                        COALESCE(upload.direct_credential_expires_at, snapshot.now)
                     ),
                     updated_at = snapshot.now
                 FROM uploads AS upload, snapshot
                 WHERE work.upload_id = $1 AND work.organization_id = $2
                   AND work.kind = 'delete' AND work.completed_at IS NULL
                   AND upload.id = work.upload_id
                   AND upload.organization_id = work.organization_id
                   AND upload.object_key = work.object_key",
            )
            .bind(upload.id.as_uuid())
            .bind(upload.tenant_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
            sqlx::query(
                "UPDATE upload_reconciliation SET completed_at = clock_timestamp(),
                 updated_at = clock_timestamp()
                 WHERE upload_id = $1 AND organization_id = $2 AND kind = 'verify'
                   AND completed_at IS NULL AND lease_token IS NULL",
            )
            .bind(upload.id.as_uuid())
            .bind(upload.tenant_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        Ok(upload)
    }
    /// Atomically abandons an unpublished upload, revokes verification/scan fences, and persists
    /// cleanup for both staging and possible raced publication objects.
    ///
    /// Cleanup is delayed until any previously leased external effect has passed its fence and, for
    /// direct uploads, until the last signed write credential has expired. Retrying abandonment is
    /// idempotent and refreshes delete intent to cover late provider writes.
    pub(crate) async fn abandon(
        &self,
        tenant_id: TenantId,
        upload_id: UploadId,
    ) -> Result<Upload, UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let row =
            sqlx::query("SELECT * FROM uploads WHERE id = $1 AND organization_id = $2 FOR UPDATE")
                .bind(upload_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| UploadError::Database)?
                .ok_or(UploadError::NotFound)?;
        let mut upload = decode_upload(&row)?;
        if upload.state == UploadState::Available {
            return Err(UploadError::State);
        }
        if matches!(
            upload.state,
            UploadState::PendingUpload | UploadState::Quarantined
        ) {
            sqlx::query(
                "UPDATE uploads
                 SET state = 'rejected', rejection_reason = 'abandoned',
                     completed_at = clock_timestamp(), updated_at = clock_timestamp(),
                     revision = revision + 1
                 WHERE id = $1 AND organization_id = $2
                   AND state IN ('pending_upload', 'quarantined')",
            )
            .bind(upload_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
            upload = fetch_upload_locked(&mut transaction, tenant_id, upload_id).await?;
        }
        if upload.rejection_reason != Some(RejectionReason::Abandoned) {
            transaction
                .commit()
                .await
                .map_err(|_| UploadError::Database)?;
            return Ok(upload);
        }
        schedule_abandoned_cleanup(&mut transaction, &upload).await?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        counter!("omnius_upload_transition_total", "transition" => "abandoned").increment(1);
        Ok(upload)
    }

    /// Atomically expires a bounded pending batch, then claims an ordered, disjoint work batch.
    /// Every row receives a distinct application-generated `UUIDv7` fence. Referenced effect input
    /// is decoded before the lease deadline is refreshed, preserving the full validated external
    /// work plus fenced-finalization budget after the claim returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration is invalid or expiry, claiming, or decoding fails.
    pub async fn claim(&self, config: &ReconcilerConfig) -> Result<Vec<LeasedWork>, UploadError> {
        config.validate()?;
        let lease_micros = postgres_interval_micros(config.lease_duration)?;
        let started = Instant::now();
        let mut tokens = Vec::with_capacity(usize::from(config.claim_batch));
        for _ in 0..config.claim_batch {
            tokens.push(Uuid::now_v7());
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        expire_pending_batch(&mut transaction, config.claim_batch).await?;
        let rows = sqlx::query(
            "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now),
             locked AS (
                SELECT work.id, work.available_at, work.created_at
                FROM upload_reconciliation AS work, snapshot
                WHERE work.completed_at IS NULL
                  AND work.available_at <= snapshot.now
                  AND work.attempt_count < $1
                  AND (work.lease_expires_at IS NULL OR work.lease_expires_at <= snapshot.now)
                ORDER BY work.available_at, work.created_at, work.id
                FOR UPDATE OF work SKIP LOCKED
                LIMIT $2
             ), numbered AS (
                SELECT id, row_number() OVER (ORDER BY available_at, created_at, id) AS ordinal
                FROM locked
             ), supplied_tokens AS (
                SELECT token, ordinal
                FROM unnest($3::uuid[]) WITH ORDINALITY AS supplied(token, ordinal)
             ), claimed AS (
                UPDATE upload_reconciliation AS work
                SET lease_owner = $4,
                    lease_token = supplied_tokens.token,
                    lease_expires_at = snapshot.now
                        + $5::bigint * INTERVAL '1 microsecond',
                    attempt_count = work.attempt_count + 1,
                    updated_at = snapshot.now
                FROM numbered
                JOIN supplied_tokens USING (ordinal)
                CROSS JOIN snapshot
                WHERE work.id = numbered.id
                RETURNING work.*
             )
             SELECT * FROM claimed ORDER BY available_at, created_at, id",
        )
        .bind(i32::from(config.max_attempts))
        .bind(i64::from(config.claim_batch))
        .bind(tokens)
        .bind(&config.lease_owner)
        .bind(lease_micros)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        let mut claimed = rows
            .iter()
            .map(decode_work)
            .collect::<Result<Vec<_>, _>>()?;
        for work in &mut claimed {
            work.upload_snapshot = fetch_claim_upload(&mut transaction, work).await?;
        }
        if !claimed.is_empty() {
            let lease_tokens = claimed
                .iter()
                .map(|work| work.lease_token.as_uuid())
                .collect::<Vec<_>>();
            let refreshed = sqlx::query(
                "UPDATE upload_reconciliation
                 SET lease_expires_at = clock_timestamp()
                        + $2::bigint * INTERVAL '1 microsecond',
                     updated_at = clock_timestamp()
                 WHERE lease_token = ANY($1) AND completed_at IS NULL",
            )
            .bind(lease_tokens)
            .bind(lease_micros)
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
            if refreshed.rows_affected()
                != u64::try_from(claimed.len()).map_err(|_| UploadError::Database)?
            {
                return Err(UploadError::Database);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        record_repository("claim", "ok", started.elapsed());
        counter!("omnius_upload_reconciliation_claimed_total").increment(claimed.len() as u64);
        Ok(claimed)
    }

    /// Records the PostgreSQL-clock start of a scan publication attempt and refreshes its lease so
    /// the validated external-effect plus finalization budget begins after this fence.
    pub(crate) async fn begin_publication(
        &self,
        work: &LeasedWork,
        lease_duration: Duration,
    ) -> Result<OffsetDateTime, UploadError> {
        if work.kind != WorkKind::Scan || lease_duration.is_zero() {
            return Err(UploadError::State);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        sqlx::query_scalar::<_, OffsetDateTime>(
            "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
             UPDATE upload_reconciliation AS work
             SET lease_expires_at = snapshot.now
                    + $3::bigint * INTERVAL '1 microsecond',
                 updated_at = snapshot.now
             FROM snapshot
             WHERE work.id = $1 AND work.lease_token = $2 AND work.kind = 'scan'
               AND work.completed_at IS NULL
               AND work.lease_expires_at > snapshot.now
             RETURNING work.updated_at",
        )
        .bind(work.id.as_uuid())
        .bind(work.lease_token.as_uuid())
        .bind(postgres_interval_micros(lease_duration)?)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)?
        .ok_or(UploadError::LostLease)
    }

    /// Completes verified content and atomically creates its scan intent under a live fence.
    ///
    /// # Errors
    ///
    /// Returns an error when the lease is lost, the work is invalid, or persistence fails.
    pub async fn complete_verification(
        &self,
        work: &LeasedWork,
        detected_mime: DeclaredMime,
    ) -> Result<(), UploadError> {
        let upload_id = work.upload_id.ok_or(UploadError::State)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        lock_live_work(&mut transaction, work, WorkKind::Verify).await?;
        let changed = sqlx::query(
            "UPDATE uploads
             SET detected_mime = $3, verified_at = clock_timestamp(),
                 updated_at = clock_timestamp(), revision = revision + 1
             WHERE id = $1 AND organization_id = $2 AND state = 'quarantined'
               AND declared_mime = $3",
        )
        .bind(upload_id.as_uuid())
        .bind(work.tenant_id.as_uuid())
        .bind(detected_mime.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        if changed.rows_affected() != 1 {
            return Err(UploadError::State);
        }
        insert_work(
            &mut transaction,
            Some(upload_id),
            work.tenant_id,
            &work.object_key,
            WorkKind::Scan,
            true,
        )
        .await?;
        finish_work(&mut transaction, work).await?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        counter!("omnius_upload_transition_total", "transition" => "verified").increment(1);
        Ok(())
    }

    /// Publishes a clean copied object, completes the scan intent, and schedules staging cleanup
    /// under its live fence. A publication-key delete that began after this copy attempt forces a
    /// safe retry instead of exposing a possibly deleted object.
    ///
    /// # Errors
    ///
    /// Returns an error when the lease is lost, the work is not publishable, or persistence fails.
    pub async fn complete_scan_clean(
        &self,
        work: &LeasedWork,
        publication_started_at: OffsetDateTime,
    ) -> Result<(), UploadError> {
        let upload_id = work.upload_id.ok_or(UploadError::State)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        lock_live_work(&mut transaction, work, WorkKind::Scan).await?;
        let upload = fetch_upload_locked(&mut transaction, work.tenant_id, upload_id).await?;
        if upload.state != UploadState::Quarantined || upload.object_key != work.object_key {
            return Err(UploadError::State);
        }
        fence_published_deletes_locked(&mut transaction, &upload, publication_started_at).await?;
        let changed = sqlx::query(
            "UPDATE uploads
             SET state = 'available', scanned_at = clock_timestamp(),
                 completed_at = clock_timestamp(), updated_at = clock_timestamp(),
                 revision = revision + 1
             WHERE id = $1 AND organization_id = $2 AND state = 'quarantined'
               AND verified_at IS NOT NULL AND detected_mime = declared_mime",
        )
        .bind(upload_id.as_uuid())
        .bind(work.tenant_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        if changed.rows_affected() != 1 {
            return Err(UploadError::State);
        }
        ensure_orphan_delete_work_locked(&mut transaction, work.tenant_id, &work.object_key)
            .await?;
        finish_work(&mut transaction, work).await?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        counter!("omnius_upload_transition_total", "transition" => "available").increment(1);
        Ok(())
    }

    /// Fails closed under a live verify/scan fence and atomically schedules deletion.
    ///
    /// # Errors
    ///
    /// Returns an error when the work is not verify or scan work, its lease is lost, or persistence
    /// fails.
    pub async fn reject_leased(
        &self,
        work: &LeasedWork,
        reason: RejectionReason,
    ) -> Result<(), UploadError> {
        let upload_id = work.upload_id.ok_or(UploadError::State)?;
        if work.kind == WorkKind::Delete {
            return Err(UploadError::State);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        lock_live_work(&mut transaction, work, work.kind).await?;
        let changed = sqlx::query(
            "UPDATE uploads
             SET state = 'rejected', rejection_reason = $3, completed_at = clock_timestamp(),
                 updated_at = clock_timestamp(), revision = revision + 1
             WHERE id = $1 AND organization_id = $2 AND state = 'quarantined'",
        )
        .bind(upload_id.as_uuid())
        .bind(work.tenant_id.as_uuid())
        .bind(reason.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        if changed.rows_affected() != 1 {
            return Err(UploadError::State);
        }
        insert_work(
            &mut transaction,
            Some(upload_id),
            work.tenant_id,
            &work.object_key,
            WorkKind::Delete,
            true,
        )
        .await?;
        finish_work(&mut transaction, work).await?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        counter!("omnius_upload_transition_total", "transition" => "rejected").increment(1);
        Ok(())
    }

    /// Completes idempotent deletion under a live fence. Orphan deletion has no upload row, while
    /// a referenced late-write repair may finalize an upload that is already `Deleted`.
    ///
    /// # Errors
    ///
    /// Returns an error when the lease is lost, a referenced upload is not rejected/deleted, or
    /// persistence fails.
    pub async fn complete_delete(&self, work: &LeasedWork) -> Result<(), UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        if let Some(upload_id) = work.upload_id {
            let upload = sqlx::query(
                "SELECT id FROM uploads
                 WHERE id = $1 AND organization_id = $2 FOR UPDATE",
            )
            .bind(upload_id.as_uuid())
            .bind(work.tenant_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
            if upload.is_none() {
                return Err(UploadError::State);
            }
        }
        lock_live_work(&mut transaction, work, WorkKind::Delete).await?;
        if let Some(upload_id) = work.upload_id {
            let changed = sqlx::query(
                "UPDATE uploads
                 SET state = 'deleted', deleted_at = clock_timestamp(),
                     updated_at = clock_timestamp(), revision = revision + 1
                 WHERE id = $1 AND organization_id = $2
                   AND state IN ('rejected', 'deleted')",
            )
            .bind(upload_id.as_uuid())
            .bind(work.tenant_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
            if changed.rows_affected() != 1 {
                return Err(UploadError::State);
            }
        }
        finish_work(&mut transaction, work).await?;
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        counter!("omnius_upload_transition_total", "transition" => "deleted").increment(1);
        Ok(())
    }

    /// Clears a live fence and schedules a bounded retry from the PostgreSQL clock.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] for a zero or overlong delay, [`UploadError::LostLease`] when
    /// the lease has expired, or [`UploadError::Database`] when persistence fails.
    pub async fn retry(
        &self,
        work: &LeasedWork,
        failure: WorkFailureCode,
        delay: Duration,
    ) -> Result<(), UploadError> {
        if delay.is_zero() || delay > Duration::from_hours(24) {
            return Err(UploadError::Invalid);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let done = sqlx::query(
            "UPDATE upload_reconciliation
             SET last_error_code = $3,
                 available_at = clock_timestamp() + $4::bigint * INTERVAL '1 microsecond',
                 lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND lease_token = $2 AND completed_at IS NULL
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(work.id.as_uuid())
        .bind(work.lease_token.as_uuid())
        .bind(failure.as_str())
        .bind(postgres_interval_micros(delay)?)
        .execute(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)?;
        if done.rows_affected() != 1 {
            return Err(UploadError::LostLease);
        }
        counter!("omnius_upload_reconciliation_retry_total", "kind" => work.kind.as_str())
            .increment(1);
        Ok(())
    }

    /// Returns whether an object key has a live authoritative upload reference in the tenant.
    /// Staging is authoritative only for live pending, quarantined, or rejected uploads; publication
    /// is authoritative only while available. Deleted rows deliberately retain no known key.
    ///
    /// # Errors
    ///
    /// Returns an error when key conversion or the database query fails.
    pub async fn object_is_known(
        &self,
        tenant_id: TenantId,
        object_key: &ObjectKey,
    ) -> Result<bool, UploadError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                SELECT 1
                FROM uploads
                WHERE organization_id = $1
                  AND (
                    (
                      object_key = $2
                      AND (
                        state IN ('quarantined', 'rejected')
                        OR (state = 'pending_upload' AND pending_expires_at > clock_timestamp())
                      )
                    )
                    OR (published_object_key = $2 AND state = 'available')
                  )
             )",
        )
        .bind(tenant_id.as_uuid())
        .bind(object_key_uuid(object_key)?)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)
    }

    /// Durably schedules idempotent deletion of an object with no state-authoritative key role. An
    /// expired pending staging reference is rejected and its referenced delete is scheduled in the
    /// same transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when key conversion or the database operation fails.
    pub async fn schedule_orphan_delete(
        &self,
        tenant_id: TenantId,
        object_key: &ObjectKey,
    ) -> Result<bool, UploadError> {
        let key = object_key_uuid(object_key)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| UploadError::Database)?;
        let rows = sqlx::query(
            "SELECT *,
                    object_key = $2 AS staging_match,
                    pending_expires_at <= clock_timestamp() AS pending_expired
             FROM uploads
             WHERE organization_id = $1
               AND (object_key = $2 OR published_object_key = $2)
             ORDER BY id
             FOR UPDATE",
        )
        .bind(tenant_id.as_uuid())
        .bind(key)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| UploadError::Database)?;
        let mut known = false;
        let mut scheduled = false;
        for row in &rows {
            let upload = decode_upload(row)?;
            let staging_match: bool = row
                .try_get("staging_match")
                .map_err(|_| UploadError::Database)?;
            let pending_expired: bool = row
                .try_get("pending_expired")
                .map_err(|_| UploadError::Database)?;
            if staging_match && upload.state == UploadState::PendingUpload && pending_expired {
                reject_expired_pending_locked(&mut transaction, &upload).await?;
                scheduled = true;
            } else if (staging_match
                && matches!(
                    upload.state,
                    UploadState::PendingUpload | UploadState::Quarantined | UploadState::Rejected
                ))
                || (!staging_match && upload.state == UploadState::Available)
            {
                known = true;
            }
        }
        if !known && !scheduled {
            let done = sqlx::query(
                "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
                 INSERT INTO upload_reconciliation (
                    id, upload_id, organization_id, object_key, kind, available_at, created_at, updated_at
                 )
                 SELECT $1, NULL, $2, $3, 'delete', snapshot.now, snapshot.now, snapshot.now
                 FROM snapshot
                 ON CONFLICT (organization_id, object_key, kind)
                 WHERE completed_at IS NULL DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(tenant_id.as_uuid())
            .bind(key)
            .execute(&mut *transaction)
            .await
            .map_err(|_| UploadError::Database)?;
            scheduled = done.rows_affected() == 1;
        }
        transaction
            .commit()
            .await
            .map_err(|_| UploadError::Database)?;
        Ok(scheduled)
    }

    /// Lists aggregate work categories using one PostgreSQL-clock snapshot and no tenant, key,
    /// filename, digest, or scanner values.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] for an invalid attempt bound or [`UploadError::Database`]
    /// when the aggregate query fails.
    pub async fn health(&self, max_attempts: u16) -> Result<UploadHealth, UploadError> {
        if max_attempts == 0 || max_attempts > 100 {
            return Err(UploadError::Invalid);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| UploadError::Database)?;
        let row = sqlx::query(
            "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
             SELECT
               COUNT(*) FILTER (
                 WHERE completed_at IS NULL AND available_at <= snapshot.now
                   AND attempt_count < $1
                   AND (lease_expires_at IS NULL OR lease_expires_at <= snapshot.now)
               ) AS ready,
               COUNT(*) FILTER (
                 WHERE completed_at IS NULL
                   AND (available_at IS NULL OR available_at > snapshot.now)
                   AND (lease_expires_at IS NULL OR lease_expires_at <= snapshot.now)
               ) AS delayed,
               COUNT(*) FILTER (
                 WHERE completed_at IS NULL AND lease_expires_at > snapshot.now
               ) AS leased,
               COUNT(*) FILTER (
                 WHERE completed_at IS NULL AND attempt_count >= $1
                   AND (lease_expires_at IS NULL OR lease_expires_at <= snapshot.now)
               ) AS exhausted
             FROM upload_reconciliation CROSS JOIN snapshot",
        )
        .bind(i32::from(max_attempts))
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| UploadError::Database)?;
        Ok(UploadHealth {
            ready: nonnegative_count(&row, "ready")?,
            delayed: nonnegative_count(&row, "delayed")?,
            leased: nonnegative_count(&row, "leased")?,
            exhausted: nonnegative_count(&row, "exhausted")?,
        })
    }
}

async fn load_or_extend_pending_upload(
    transaction: &mut Transaction<'_, Postgres>,
    draft: &UploadDraft,
    pending_micros: i64,
    inserted: bool,
) -> Result<Upload, UploadError> {
    let row = sqlx::query(
        "SELECT *, pending_expires_at <= clock_timestamp() AS pending_expired
         FROM uploads WHERE id = $1 AND organization_id = $2 FOR UPDATE",
    )
    .bind(draft.id.as_uuid())
    .bind(draft.tenant_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?
    .ok_or(UploadError::Conflict)?;
    let mut upload = decode_upload(&row)?;
    if !same_identity(&upload, draft) {
        return Err(UploadError::Conflict);
    }
    if !inserted && upload.state == UploadState::PendingUpload {
        let pending_expired: bool = row
            .try_get("pending_expired")
            .map_err(|_| UploadError::Database)?;
        if pending_expired {
            reject_expired_pending_locked(transaction, &upload).await?;
            upload = fetch_upload_locked(transaction, upload.tenant_id, upload.id).await?;
        } else {
            upload = extend_pending_upload_locked(transaction, &upload, pending_micros).await?;
        }
    }
    Ok(upload)
}

async fn extend_pending_upload_locked(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &Upload,
    pending_micros: i64,
) -> Result<Upload, UploadError> {
    let row = sqlx::query(
        "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
         UPDATE uploads
         SET pending_expires_at = GREATEST(
                pending_expires_at,
                snapshot.now + $3::bigint * INTERVAL '1 microsecond'
             ),
             updated_at = snapshot.now,
             revision = revision + 1
         FROM snapshot
         WHERE id = $1 AND organization_id = $2 AND state = 'pending_upload'
           AND pending_expires_at > snapshot.now
         RETURNING uploads.*",
    )
    .bind(upload.id.as_uuid())
    .bind(upload.tenant_id.as_uuid())
    .bind(pending_micros)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?
    .ok_or(UploadError::State)?;
    decode_upload(&row)
}

async fn ensure_dormant_verify_work(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &Upload,
) -> Result<(), UploadError> {
    if upload.state == UploadState::PendingUpload {
        insert_work(
            transaction,
            Some(upload.id),
            upload.tenant_id,
            &upload.object_key,
            WorkKind::Verify,
            false,
        )
        .await?;
    }
    Ok(())
}

async fn fetch_claim_upload(
    transaction: &mut Transaction<'_, Postgres>,
    work: &LeasedWork,
) -> Result<Option<Upload>, UploadError> {
    if work.kind == WorkKind::Delete {
        return Ok(None);
    }
    let upload_id = work.upload_id.ok_or(UploadError::State)?;
    let row = sqlx::query(
        "SELECT * FROM uploads
         WHERE id = $1 AND organization_id = $2 AND object_key = $3",
    )
    .bind(upload_id.as_uuid())
    .bind(work.tenant_id.as_uuid())
    .bind(object_key_uuid(&work.object_key)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?
    .ok_or(UploadError::State)?;
    decode_upload(&row).map(Some)
}

async fn fetch_upload_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    upload_id: UploadId,
) -> Result<Upload, UploadError> {
    let row =
        sqlx::query("SELECT * FROM uploads WHERE id = $1 AND organization_id = $2 FOR UPDATE")
            .bind(upload_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| UploadError::Database)?
            .ok_or(UploadError::NotFound)?;
    decode_upload(&row)
}
async fn fence_published_deletes_locked(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &Upload,
    publication_started_at: OffsetDateTime,
) -> Result<(), UploadError> {
    let rows = sqlx::query(
        "SELECT completed_at,
                completed_at IS NULL
                  AND COALESCE(lease_expires_at > clock_timestamp(), FALSE) AS lease_live
         FROM upload_reconciliation
         WHERE organization_id = $1 AND object_key = $2 AND kind = 'delete'
           AND (completed_at IS NULL OR completed_at >= $3)
         ORDER BY created_at, id
         FOR UPDATE",
    )
    .bind(upload.tenant_id.as_uuid())
    .bind(object_key_uuid(&upload.published_object_key)?)
    .bind(publication_started_at)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    for row in &rows {
        let completed_at: Option<OffsetDateTime> = row
            .try_get("completed_at")
            .map_err(|_| UploadError::Database)?;
        let lease_live: bool = row
            .try_get("lease_live")
            .map_err(|_| UploadError::Database)?;
        if completed_at.is_some() || lease_live {
            return Err(UploadError::LostLease);
        }
    }
    sqlx::query(
        "UPDATE upload_reconciliation
         SET completed_at = clock_timestamp(), last_error_code = NULL,
             lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
             updated_at = clock_timestamp()
         WHERE organization_id = $1 AND object_key = $2 AND kind = 'delete'
           AND completed_at IS NULL",
    )
    .bind(upload.tenant_id.as_uuid())
    .bind(object_key_uuid(&upload.published_object_key)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    Ok(())
}

async fn reject_expired_pending_locked(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &Upload,
) -> Result<(), UploadError> {
    let changed = sqlx::query(
        "UPDATE uploads
         SET state = 'rejected', rejection_reason = 'pending_expired',
             completed_at = clock_timestamp(), updated_at = clock_timestamp(),
             revision = revision + 1
         WHERE id = $1 AND organization_id = $2 AND state = 'pending_upload'
           AND pending_expires_at <= clock_timestamp()",
    )
    .bind(upload.id.as_uuid())
    .bind(upload.tenant_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    if changed.rows_affected() != 1 {
        return Err(UploadError::State);
    }
    sqlx::query(
        "UPDATE upload_reconciliation
         SET completed_at = clock_timestamp(), last_error_code = NULL,
             lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
             updated_at = clock_timestamp()
         WHERE upload_id = $1 AND organization_id = $2 AND kind = 'verify'
           AND completed_at IS NULL",
    )
    .bind(upload.id.as_uuid())
    .bind(upload.tenant_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    ensure_referenced_delete_work_locked(transaction, upload).await
}

async fn schedule_abandoned_cleanup(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &Upload,
) -> Result<(), UploadError> {
    let cleanup_not_before = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT GREATEST(
            clock_timestamp(),
            COALESCE(MAX(lease_expires_at), clock_timestamp())
         )
         FROM upload_reconciliation
         WHERE upload_id = $1 AND organization_id = $2
           AND kind IN ('verify', 'scan') AND completed_at IS NULL",
    )
    .bind(upload.id.as_uuid())
    .bind(upload.tenant_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    sqlx::query(
        "UPDATE upload_reconciliation
         SET completed_at = clock_timestamp(), last_error_code = NULL,
             lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
             updated_at = clock_timestamp()
         WHERE upload_id = $1 AND organization_id = $2
           AND kind IN ('verify', 'scan') AND completed_at IS NULL",
    )
    .bind(upload.id.as_uuid())
    .bind(upload.tenant_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    ensure_referenced_delete_work_locked(transaction, upload).await?;
    ensure_orphan_delete_work_locked(transaction, upload.tenant_id, &upload.published_object_key)
        .await?;
    sqlx::query(
        "UPDATE upload_reconciliation
         SET available_at = GREATEST(
                COALESCE(available_at, $3),
                $3
             ),
             updated_at = clock_timestamp()
         WHERE organization_id = $1
           AND object_key IN ($2, $4)
           AND kind = 'delete' AND completed_at IS NULL",
    )
    .bind(upload.tenant_id.as_uuid())
    .bind(object_key_uuid(&upload.object_key)?)
    .bind(cleanup_not_before)
    .bind(object_key_uuid(&upload.published_object_key)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    Ok(())
}

async fn ensure_referenced_delete_work_locked(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &Upload,
) -> Result<(), UploadError> {
    insert_work(
        transaction,
        Some(upload.id),
        upload.tenant_id,
        &upload.object_key,
        WorkKind::Delete,
        true,
    )
    .await?;
    sqlx::query(
        "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
         UPDATE upload_reconciliation AS work
         SET available_at = GREATEST(
                COALESCE(work.available_at, snapshot.now),
                COALESCE(upload.direct_credential_expires_at, snapshot.now)
             ),
             attempt_count = CASE
                WHEN work.lease_expires_at IS NULL OR work.lease_expires_at <= snapshot.now
                THEN 0
                ELSE work.attempt_count
             END,
             last_error_code = CASE
                WHEN work.lease_expires_at IS NULL OR work.lease_expires_at <= snapshot.now
                THEN NULL
                ELSE work.last_error_code
             END,
             updated_at = snapshot.now
         FROM uploads AS upload, snapshot
         WHERE work.upload_id = $1 AND work.organization_id = $2
           AND work.kind = 'delete' AND work.completed_at IS NULL
           AND upload.id = work.upload_id
           AND upload.organization_id = work.organization_id
           AND upload.object_key = work.object_key",
    )
    .bind(upload.id.as_uuid())
    .bind(upload.tenant_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    Ok(())
}

async fn ensure_orphan_delete_work_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    object_key: &ObjectKey,
) -> Result<(), UploadError> {
    insert_work(
        transaction,
        None,
        tenant_id,
        object_key,
        WorkKind::Delete,
        true,
    )
    .await?;
    sqlx::query(
        "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
         UPDATE upload_reconciliation AS work
         SET available_at = GREATEST(COALESCE(work.available_at, snapshot.now), snapshot.now),
             attempt_count = CASE
                WHEN work.lease_expires_at IS NULL OR work.lease_expires_at <= snapshot.now
                THEN 0
                ELSE work.attempt_count
             END,
             last_error_code = CASE
                WHEN work.lease_expires_at IS NULL OR work.lease_expires_at <= snapshot.now
                THEN NULL
                ELSE work.last_error_code
             END,
             updated_at = snapshot.now
         FROM snapshot
         WHERE work.organization_id = $1 AND work.object_key = $2
           AND work.kind = 'delete' AND work.completed_at IS NULL",
    )
    .bind(tenant_id.as_uuid())
    .bind(object_key_uuid(object_key)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    Ok(())
}

async fn expire_pending_batch(
    transaction: &mut Transaction<'_, Postgres>,
    limit: u16,
) -> Result<(), UploadError> {
    let rows = sqlx::query(
        "SELECT *
         FROM uploads
         WHERE state = 'pending_upload' AND pending_expires_at <= clock_timestamp()
         ORDER BY pending_expires_at, id
         FOR UPDATE SKIP LOCKED
         LIMIT $1",
    )
    .bind(i64::from(limit))
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    for row in &rows {
        let upload = decode_upload(row)?;
        reject_expired_pending_locked(transaction, &upload).await?;
    }
    Ok(())
}

async fn insert_work(
    transaction: &mut Transaction<'_, Postgres>,
    upload_id: Option<UploadId>,
    tenant_id: TenantId,
    object_key: &ObjectKey,
    kind: WorkKind,
    ready: bool,
) -> Result<(), UploadError> {
    sqlx::query(
        "WITH snapshot AS MATERIALIZED (SELECT clock_timestamp() AS now)
         INSERT INTO upload_reconciliation (
            id, upload_id, organization_id, object_key, kind, available_at, created_at, updated_at
         )
         SELECT $1, $2, $3, $4, $5,
                CASE WHEN $6 THEN snapshot.now ELSE NULL END,
                snapshot.now, snapshot.now
         FROM snapshot
         ON CONFLICT (organization_id, object_key, kind)
         WHERE completed_at IS NULL DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(upload_id.map(UploadId::as_uuid))
    .bind(tenant_id.as_uuid())
    .bind(object_key_uuid(object_key)?)
    .bind(kind.as_str())
    .bind(ready)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    Ok(())
}

async fn lock_live_work(
    transaction: &mut Transaction<'_, Postgres>,
    work: &LeasedWork,
    expected_kind: WorkKind,
) -> Result<(), UploadError> {
    if work.kind != expected_kind {
        return Err(UploadError::State);
    }
    let row = sqlx::query(
        "SELECT id FROM upload_reconciliation
         WHERE id = $1 AND lease_token = $2 AND kind = $3
           AND completed_at IS NULL AND lease_expires_at > clock_timestamp()
         FOR UPDATE",
    )
    .bind(work.id.as_uuid())
    .bind(work.lease_token.as_uuid())
    .bind(expected_kind.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    if row.is_some() {
        Ok(())
    } else {
        Err(UploadError::LostLease)
    }
}

async fn finish_work(
    transaction: &mut Transaction<'_, Postgres>,
    work: &LeasedWork,
) -> Result<(), UploadError> {
    let done = sqlx::query(
        "UPDATE upload_reconciliation
         SET completed_at = clock_timestamp(), last_error_code = NULL,
             lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
             updated_at = clock_timestamp()
         WHERE id = $1 AND lease_token = $2 AND completed_at IS NULL
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(work.id.as_uuid())
    .bind(work.lease_token.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|_| UploadError::Database)?;
    if done.rows_affected() == 1 {
        Ok(())
    } else {
        Err(UploadError::LostLease)
    }
}

fn decode_upload(row: &PgRow) -> Result<Upload, UploadError> {
    let digest: Vec<u8> = row
        .try_get("expected_sha256")
        .map_err(|_| UploadError::Database)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| UploadError::Database)?;
    let object_key: Uuid = row
        .try_get("object_key")
        .map_err(|_| UploadError::Database)?;
    let published_object_key: Uuid = row
        .try_get("published_object_key")
        .map_err(|_| UploadError::Database)?;
    let detected_mime: Option<String> = row
        .try_get("detected_mime")
        .map_err(|_| UploadError::Database)?;
    let rejection_reason: Option<String> = row
        .try_get("rejection_reason")
        .map_err(|_| UploadError::Database)?;
    let declared_size: i64 = row
        .try_get("declared_size")
        .map_err(|_| UploadError::Database)?;
    Ok(Upload {
        id: UploadId::from_uuid(row.try_get("id").map_err(|_| UploadError::Database)?)?,
        tenant_id: TenantId::from_uuid(
            row.try_get("organization_id")
                .map_err(|_| UploadError::Database)?,
        )
        .map_err(|_| UploadError::Database)?,
        owner_id: SubjectId::from_uuid(row.try_get("owner_id").map_err(|_| UploadError::Database)?)
            .map_err(|_| UploadError::Database)?,
        object_key: ObjectKey::from_str(&object_key.hyphenated().to_string())
            .map_err(|_| UploadError::Database)?,
        published_object_key: ObjectKey::from_str(&published_object_key.hyphenated().to_string())
            .map_err(|_| UploadError::Database)?,
        filename: NormalizedFilename::parse(
            row.try_get::<String, _>("filename")
                .map_err(|_| UploadError::Database)?,
        )?,
        declared_size: u64::try_from(declared_size).map_err(|_| UploadError::Database)?,
        expected_sha256: Sha256Digest::from_bytes(digest),
        declared_mime: row
            .try_get::<String, _>("declared_mime")
            .map_err(|_| UploadError::Database)?
            .parse()
            .map_err(|_| UploadError::Database)?,
        direct_credential_expires_at: row
            .try_get("direct_credential_expires_at")
            .map_err(|_| UploadError::Database)?,
        pending_expires_at: row
            .try_get("pending_expires_at")
            .map_err(|_| UploadError::Database)?,
        detected_mime: detected_mime
            .map(|value| value.parse().map_err(|_| UploadError::Database))
            .transpose()?,
        state: UploadState::parse(
            &row.try_get::<String, _>("state")
                .map_err(|_| UploadError::Database)?,
        )?,
        rejection_reason: rejection_reason
            .map(|value| RejectionReason::parse(&value))
            .transpose()?,
        revision: row.try_get("revision").map_err(|_| UploadError::Database)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| UploadError::Database)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| UploadError::Database)?,
    })
}

fn decode_work(row: &PgRow) -> Result<LeasedWork, UploadError> {
    let token: Uuid = row
        .try_get::<Option<Uuid>, _>("lease_token")
        .map_err(|_| UploadError::Database)?
        .ok_or(UploadError::Database)?;
    let key: Uuid = row
        .try_get("object_key")
        .map_err(|_| UploadError::Database)?;
    let attempts: i32 = row
        .try_get("attempt_count")
        .map_err(|_| UploadError::Database)?;
    Ok(LeasedWork {
        id: WorkId::from_uuid(row.try_get("id").map_err(|_| UploadError::Database)?)?,
        upload_id: row
            .try_get::<Option<Uuid>, _>("upload_id")
            .map_err(|_| UploadError::Database)?
            .map(UploadId::from_uuid)
            .transpose()?,
        tenant_id: TenantId::from_uuid(
            row.try_get("organization_id")
                .map_err(|_| UploadError::Database)?,
        )
        .map_err(|_| UploadError::Database)?,
        object_key: ObjectKey::from_str(&key.hyphenated().to_string())
            .map_err(|_| UploadError::Database)?,
        kind: WorkKind::parse(
            &row.try_get::<String, _>("kind")
                .map_err(|_| UploadError::Database)?,
        )?,
        lease_token: LeaseToken::from_uuid(token)?,
        attempt_count: u16::try_from(attempts).map_err(|_| UploadError::Database)?,
        upload_snapshot: None,
    })
}

fn same_identity(upload: &Upload, draft: &UploadDraft) -> bool {
    upload.id == draft.id
        && upload.tenant_id == draft.tenant_id
        && upload.owner_id == draft.owner_id
        && upload.filename == draft.filename
        && upload.declared_size == draft.declared_size
        && upload.expected_sha256 == draft.expected_sha256
        && upload.declared_mime == draft.declared_mime
}

fn object_key_uuid(key: &ObjectKey) -> Result<Uuid, UploadError> {
    Uuid::parse_str(key.as_str()).map_err(|_| UploadError::Invalid)
}

fn nonnegative_count(row: &PgRow, field: &str) -> Result<u64, UploadError> {
    let count: i64 = row.try_get(field).map_err(|_| UploadError::Database)?;
    u64::try_from(count).map_err(|_| UploadError::Database)
}

fn result_label<T>(result: &Result<T, UploadError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(UploadError::NotFound) => "not_found",
        Err(UploadError::Conflict) => "conflict",
        Err(_) => "error",
    }
}

fn record_repository(operation: &'static str, result: &'static str, elapsed: Duration) {
    histogram!("omnius_upload_repository_duration_seconds", "operation" => operation, "result" => result)
        .record(elapsed.as_secs_f64());
}
