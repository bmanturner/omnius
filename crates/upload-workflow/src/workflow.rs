use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use http::{
    HeaderMap, HeaderValue,
    header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
};
use metrics::counter;
use omnius_auth_core::{SubjectId, TenantId};
use omnius_object_storage::{
    BlobStore, BlobStoreError, ByteStream, GetCondition, GetRequest, ListRequest, ObjectKey,
    OperationContext, PresignMethod, PresignRequest, PresignedUrl, PutRequest, WriteCondition,
};
use time::OffsetDateTime;

use crate::{
    DeclaredMime, NormalizedFilename, PostgresUploadRepository, ReconcilerConfig, RejectionReason,
    Sha256Digest, Upload, UploadAction, UploadAuthorization, UploadAuthorizer, UploadError,
    UploadId, UploadState, max_object_bytes,
    repository::{PostWriteDisposition, UploadDraft},
};

const DIRECT_CREDENTIAL_CLOCK_SKEW: Duration = Duration::from_secs(30);
const MAX_PENDING_UPLOAD_TTL: Duration = Duration::from_hours(24);

/// Idempotent initiation input. The `UUIDv7` `upload_id` is the application idempotency identity.
#[derive(Clone, Debug)]
pub struct InitiateUploadRequest {
    /// Caller-generated or server-issued retry-stable upload identifier.
    pub upload_id: UploadId,
    /// Tenant namespace established by authentication.
    pub tenant_id: TenantId,
    /// Authenticated actor and durable owner.
    pub actor_id: SubjectId,
    /// Untrusted display filename to normalize before persistence.
    pub filename: String,
    /// Exact object byte count.
    pub declared_size: u64,
    /// Exact SHA-256 digest required by direct and proxied upload paths.
    pub expected_sha256: Sha256Digest,
    /// Strict declared MIME allowlist value.
    pub declared_mime: DeclaredMime,
    /// Short-lived direct-upload form validity.
    pub direct_upload_expires_in: Duration,
    /// Authorized window for supplying bytes and completing the upload (at most 24 hours).
    ///
    /// This must cover `direct_upload_expires_in` plus the workflow's conservative 30-second
    /// credential clock-skew margin.
    pub pending_upload_ttl: Duration,
}

/// Provider-signed direct upload form. Its debug representation never exposes credentials.
pub struct DirectUploadForm {
    /// Durable upload identifier used for completion.
    pub upload_id: UploadId,
    signed: PresignedUrl,
}

impl DirectUploadForm {
    /// Explicitly exposes the credential-bearing signed URL for the authorized response only.
    #[must_use]
    pub fn signed(&self) -> &PresignedUrl {
        &self.signed
    }
}

impl fmt::Debug for DirectUploadForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectUploadForm")
            .field("upload_id", &self.upload_id)
            .finish_non_exhaustive()
    }
}

/// Contract for proxying an exact stream through [`UploadWorkflow::put_proxied`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxiedUploadContract {
    /// Durable upload identifier.
    pub upload_id: UploadId,
    /// Exact accepted byte count.
    pub declared_size: u64,
    /// Integrity requirement enforced while streaming.
    pub expected_sha256: Sha256Digest,
}
/// Credential-free result for an idempotent initiation retry after upload completion began.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadyStartedUpload {
    /// Durable upload identifier.
    pub upload_id: UploadId,
    /// Current non-pending state.
    pub state: UploadState,
}

/// Safe initiation result selected from persisted state and provider capabilities.
#[derive(Debug)]
pub enum InitiatedUpload {
    /// Integrity-bound provider-native upload form, issued only while pending.
    Direct(DirectUploadForm),
    /// Server proxy contract for providers without safe PUT signing, issued only while pending.
    Proxied(ProxiedUploadContract),
    /// Credential-free idempotent result once completion, verification, or deletion has begun.
    AlreadyStarted(AlreadyStartedUpload),
}

/// Result of an idempotent proxied byte transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxiedUploadResult {
    /// The exact declared stream was stored, possibly replacing an identical retry delivery.
    Stored,
}

/// Independently authorized upload-completion input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteUploadRequest {
    /// Retry-stable upload identifier.
    pub upload_id: UploadId,
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Authenticated actor.
    pub actor_id: SubjectId,
}

/// Safe download input. Serving never returns a presigned provider GET.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenDownloadRequest {
    /// Available upload identifier.
    pub upload_id: UploadId,
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Authenticated actor.
    pub actor_id: SubjectId,
}

/// Attachment-only, checksum-checking response body and fixed security headers.
pub struct SafeDownload {
    /// `Content-Type`, exact length, safe attachment filename, and `nosniff` headers.
    pub headers: HeaderMap,
    /// Full object stream; a provider change or checksum mismatch terminates with a safe error.
    pub body: ByteStream,
}

impl fmt::Debug for SafeDownload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeDownload")
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// Application workflow that keeps PostgreSQL authoritative and object storage as tenant-scoped
/// byte transport. No method holds a database transaction across an object-store operation.
#[derive(Clone)]
pub struct UploadWorkflow {
    repository: PostgresUploadRepository,
    blob_store: BlobStore,
    authorizer: Arc<dyn UploadAuthorizer>,
}

impl UploadWorkflow {
    /// Creates a workflow from narrow production ports.
    #[must_use]
    pub fn new(
        repository: PostgresUploadRepository,
        blob_store: BlobStore,
        authorizer: Arc<dyn UploadAuthorizer>,
    ) -> Self {
        Self {
            repository,
            blob_store,
            authorizer,
        }
    }

    /// Authorizes initiation and persists immutable quarantine identity plus dormant verify intent.
    /// Upload credentials are minted only while the persisted state remains `PendingUpload`.
    /// Retrying after completion began returns a credential-free [`InitiatedUpload::AlreadyStarted`]
    /// outcome, so no later state can be overwritten without fresh verification and scanning.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input or when authorization, persistence, or credential issuance
    /// fails.
    pub async fn initiate(
        &self,
        context: &OperationContext,
        request: InitiateUploadRequest,
    ) -> Result<InitiatedUpload, UploadError> {
        let credential_lifetime = request
            .direct_upload_expires_in
            .checked_add(DIRECT_CREDENTIAL_CLOCK_SKEW)
            .ok_or(UploadError::Invalid)?;
        if request.declared_size > max_object_bytes()
            || request.direct_upload_expires_in.is_zero()
            || request.direct_upload_expires_in.subsec_nanos() != 0
            || request.pending_upload_ttl.is_zero()
            || request.pending_upload_ttl > MAX_PENDING_UPLOAD_TTL
            || request.pending_upload_ttl < credential_lifetime
        {
            return Err(UploadError::Invalid);
        }
        let filename = NormalizedFilename::normalize(&request.filename)?;
        self.authorizer
            .authorize(UploadAuthorization {
                action: UploadAction::Initiate,
                tenant_id: request.tenant_id,
                actor_id: request.actor_id,
                upload_id: request.upload_id,
                owner_id: request.actor_id,
            })
            .await?;

        let candidate = UploadDraft {
            id: request.upload_id,
            tenant_id: request.tenant_id,
            owner_id: request.actor_id,
            object_key: ObjectKey::new(),
            published_object_key: ObjectKey::new(),
            filename,
            declared_size: request.declared_size,
            expected_sha256: request.expected_sha256,
            declared_mime: request.declared_mime,
            pending_ttl: request.pending_upload_ttl,
        };
        let upload = self.repository.initiate(&candidate).await?;
        if let Some(outcome) = already_started_outcome(&upload) {
            return Ok(outcome);
        }
        let presigned = self
            .blob_store
            .presign(
                context,
                PresignRequest {
                    tenant_id: upload.tenant_id,
                    key: upload.object_key.clone(),
                    method: PresignMethod::Put {
                        declared_length: upload.declared_size,
                        expected_sha256: upload.expected_sha256.as_bytes(),
                    },
                    expires_in: request.direct_upload_expires_in,
                },
            )
            .await;
        match presigned {
            Ok(signed) => {
                let persisted = self
                    .repository
                    .persist_direct_credential_expiry(
                        upload.tenant_id,
                        upload.id,
                        credential_lifetime,
                        request.pending_upload_ttl,
                    )
                    .await?;
                if persisted {
                    Ok(InitiatedUpload::Direct(DirectUploadForm {
                        upload_id: upload.id,
                        signed,
                    }))
                } else {
                    let current = self.repository.lookup(upload.tenant_id, upload.id).await?;
                    already_started_outcome(&current).ok_or(UploadError::State)
                }
            }
            Err(BlobStoreError::Unsupported) => {
                Ok(InitiatedUpload::Proxied(ProxiedUploadContract {
                    upload_id: upload.id,
                    declared_size: upload.declared_size,
                    expected_sha256: upload.expected_sha256,
                }))
            }
            Err(error) => Err(map_blob_error(error)),
        }
    }

    /// Streams a proxied upload into its random server-owned quarantine key with exact size and
    /// checksum enforcement. Overwrite enables bounded multipart delivery; every authorized retry
    /// is constrained to the same immutable length and digest. Consequently, completion,
    /// verification, or publication racing the post-write fence can only observe or receive
    /// identical bytes. Rejection, deletion, and pending expiry instead persist a fresh delete
    /// intent before this method returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the upload cannot be found or authorized, is no longer eligible after
    /// the write, or the object-store write fails.
    pub async fn put_proxied(
        &self,
        context: &OperationContext,
        tenant_id: TenantId,
        actor_id: SubjectId,
        upload_id: UploadId,
        stream: ByteStream,
    ) -> Result<ProxiedUploadResult, UploadError> {
        let upload = self.repository.lookup(tenant_id, upload_id).await?;
        self.authorizer
            .authorize(UploadAuthorization {
                action: UploadAction::Initiate,
                tenant_id,
                actor_id,
                upload_id,
                owner_id: upload.owner_id,
            })
            .await?;
        if !self
            .repository
            .pending_is_live(upload.tenant_id, upload.id)
            .await?
        {
            return Err(UploadError::State);
        }
        let result = self
            .blob_store
            .put_stream(
                context,
                PutRequest {
                    tenant_id,
                    key: upload.object_key,
                    declared_length: upload.declared_size,
                    expected_sha256: upload.expected_sha256.as_bytes(),
                    content_type: Some(upload.declared_mime.as_str().to_owned()),
                    metadata: BTreeMap::new(),
                    condition: WriteCondition::Overwrite,
                    stream,
                },
            )
            .await;
        result.map_err(map_blob_error)?;
        match self
            .repository
            .fence_proxied_write(upload.tenant_id, upload.id)
            .await?
        {
            PostWriteDisposition::SafeToAcknowledge => Ok(ProxiedUploadResult::Stored),
            PostWriteDisposition::DeleteScheduled => Err(UploadError::State),
        }
    }

    /// Re-authorizes completion, checks provider metadata outside a transaction, and idempotently
    /// activates durable full-stream verification. Size mismatch fails closed and schedules delete.
    ///
    /// # Errors
    ///
    /// Returns an error when the upload cannot be found or authorized, its object is missing or has
    /// an invalid size, or persistence or object storage fails.
    pub async fn complete(
        &self,
        context: &OperationContext,
        request: CompleteUploadRequest,
    ) -> Result<Upload, UploadError> {
        let upload = self
            .repository
            .lookup(request.tenant_id, request.upload_id)
            .await?;
        self.authorizer
            .authorize(UploadAuthorization {
                action: UploadAction::Complete,
                tenant_id: request.tenant_id,
                actor_id: request.actor_id,
                upload_id: request.upload_id,
                owner_id: upload.owner_id,
            })
            .await?;
        if upload.state != UploadState::PendingUpload {
            return Ok(upload);
        }
        let metadata = match self
            .blob_store
            .head(context, upload.tenant_id, &upload.object_key)
            .await
        {
            Ok(metadata) => metadata,
            Err(BlobStoreError::NotFound) => {
                let _ = self
                    .repository
                    .reject_pending(upload.tenant_id, upload.id, RejectionReason::MissingObject)
                    .await?;
                return Err(UploadError::NotFound);
            }
            Err(error) => return Err(map_blob_error(error)),
        };
        if metadata.size != upload.declared_size {
            let _ = self
                .repository
                .reject_pending(upload.tenant_id, upload.id, RejectionReason::SizeMismatch)
                .await?;
            return Err(UploadError::SizeMismatch);
        }
        let completed = self
            .repository
            .activate_verification(upload.tenant_id, upload.id)
            .await?;
        let result = match completed.state {
            UploadState::Quarantined => "quarantined",
            UploadState::Rejected => "expired",
            _ => "unchanged",
        };
        counter!("omnius_upload_completion_total", "result" => result).increment(1);
        Ok(completed)
    }

    /// Re-authorizes download, requires durable availability, and opens the isolated publication
    /// object for a checksum-verifying proxy with fixed attachment and `nosniff` response headers.
    ///
    /// # Errors
    ///
    /// Returns an error when the upload cannot be found or authorized, is unavailable, has invalid
    /// metadata, or its published object cannot be opened.
    pub async fn open_download(
        &self,
        context: &OperationContext,
        request: OpenDownloadRequest,
    ) -> Result<SafeDownload, UploadError> {
        let upload = self
            .repository
            .lookup(request.tenant_id, request.upload_id)
            .await?;
        self.authorizer
            .authorize(UploadAuthorization {
                action: UploadAction::Download,
                tenant_id: request.tenant_id,
                actor_id: request.actor_id,
                upload_id: request.upload_id,
                owner_id: upload.owner_id,
            })
            .await?;
        if upload.state != UploadState::Available {
            return Err(UploadError::State);
        }
        let detected = upload.detected_mime.ok_or(UploadError::State)?;
        let object = self
            .blob_store
            .get_stream(
                context,
                GetRequest {
                    tenant_id: upload.tenant_id,
                    key: upload.published_object_key,
                    range: None,
                    condition: GetCondition::default(),
                    expected_sha256: Some(upload.expected_sha256.as_bytes()),
                },
            )
            .await
            .map_err(map_blob_error)?;
        if object.metadata.size != upload.declared_size {
            return Err(UploadError::SizeMismatch);
        }
        let mut headers = HeaderMap::with_capacity(4);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(detected.as_str()));
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&upload.declared_size.to_string())
                .map_err(|_| UploadError::State)?,
        );
        headers.insert(CONTENT_DISPOSITION, content_disposition(&upload.filename)?);
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        Ok(SafeDownload {
            headers,
            body: object.stream,
        })
    }

    /// Lists one tenant's object namespace and durably schedules old unreferenced keys for deletion.
    /// A second database check in the scheduling statement closes the list/insert race.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page size or when listing objects or scheduling deletion
    /// fails.
    pub async fn repair_orphans(
        &self,
        context: &OperationContext,
        tenant_id: TenantId,
        page_size: u16,
        config: &ReconcilerConfig,
    ) -> Result<u64, UploadError> {
        if page_size == 0 {
            return Err(UploadError::Invalid);
        }
        let grace_seconds =
            i64::try_from(config.orphan_grace.as_secs()).map_err(|_| UploadError::Invalid)?;
        let cutoff = OffsetDateTime::now_utc()
            .unix_timestamp()
            .saturating_sub(grace_seconds);
        let mut cursor = None;
        let mut scheduled = 0_u64;
        loop {
            let page = self
                .blob_store
                .list(
                    context,
                    ListRequest {
                        tenant_id,
                        limit: page_size,
                        cursor,
                    },
                )
                .await
                .map_err(map_blob_error)?;
            for item in &page.items {
                if item.last_modified.timestamp() <= cutoff
                    && !self
                        .repository
                        .object_is_known(tenant_id, &item.key)
                        .await?
                    && self
                        .repository
                        .schedule_orphan_delete(tenant_id, &item.key)
                        .await?
                {
                    scheduled = scheduled.saturating_add(1);
                }
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        counter!("omnius_upload_orphan_scheduled_total").increment(scheduled);
        Ok(scheduled)
    }
}

fn already_started_outcome(upload: &Upload) -> Option<InitiatedUpload> {
    (upload.state != UploadState::PendingUpload).then_some(InitiatedUpload::AlreadyStarted(
        AlreadyStartedUpload {
            upload_id: upload.id,
            state: upload.state,
        },
    ))
}

fn content_disposition(filename: &NormalizedFilename) -> Result<HeaderValue, UploadError> {
    let fallback: String = filename
        .as_str()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, ' ' | '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let mut encoded = String::with_capacity(filename.as_str().len() * 3);
    for byte in filename.as_str().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    HeaderValue::from_str(&format!(
        "attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"
    ))
    .map_err(|_| UploadError::Invalid)
}

pub(crate) fn map_blob_error(error: BlobStoreError) -> UploadError {
    match error {
        BlobStoreError::NotFound => UploadError::NotFound,
        BlobStoreError::Size => UploadError::SizeMismatch,
        BlobStoreError::Checksum => UploadError::ChecksumMismatch,
        BlobStoreError::Timeout => UploadError::Timeout,
        BlobStoreError::Cancelled | BlobStoreError::Shutdown => UploadError::Cancelled,
        BlobStoreError::Invalid | BlobStoreError::Metadata => UploadError::Invalid,
        _ => UploadError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use omnius_auth_core::{SubjectId, TenantId};
    use omnius_object_storage::ObjectKey;
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn initiation_retry_never_returns_credentials_after_pending_state() -> Result<(), UploadError> {
        for state in [
            UploadState::Quarantined,
            UploadState::Available,
            UploadState::Rejected,
            UploadState::Deleted,
        ] {
            let upload = upload_in_state(state)?;
            assert!(matches!(
                already_started_outcome(&upload),
                Some(InitiatedUpload::AlreadyStarted(AlreadyStartedUpload {
                    upload_id,
                    state: returned_state,
                })) if upload_id == upload.id && returned_state == state
            ));
        }
        assert!(already_started_outcome(&upload_in_state(UploadState::PendingUpload)?).is_none());
        Ok(())
    }

    fn upload_in_state(state: UploadState) -> Result<Upload, UploadError> {
        Ok(Upload {
            id: UploadId::new(),
            tenant_id: TenantId::new(),
            owner_id: SubjectId::new(),
            object_key: ObjectKey::new(),
            published_object_key: ObjectKey::new(),
            filename: NormalizedFilename::normalize("safe.pdf")?,
            declared_size: 5,
            expected_sha256: Sha256Digest::from_bytes([7; 32]),
            declared_mime: DeclaredMime::Pdf,
            direct_credential_expires_at: None,
            pending_expires_at: OffsetDateTime::UNIX_EPOCH + Duration::from_secs(60),
            detected_mime: (state != UploadState::PendingUpload).then_some(DeclaredMime::Pdf),
            state,
            rejection_reason: matches!(state, UploadState::Rejected | UploadState::Deleted)
                .then_some(RejectionReason::Malware),
            revision: 2,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        })
    }
}
