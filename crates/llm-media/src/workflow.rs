use std::{
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_llm_core::BinarySource;
use omnius_object_storage::ObjectKey;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::{
    AuthorizationRequest, ClaimReconciliationRequest, CleanReadRequest, CompleteDeletionRequest,
    DeleteCause, DeleteObjectRequest, DeleteRequestOutcome, DeleteResult, ExpectedMedia,
    MediaAction, MediaAuthorization, MediaError, MediaId, MediaKind, MediaObject, MediaOrigin,
    MediaPolicy, MediaReference, MediaRejection, MediaRepository, MediaScanner, MediaState,
    PublishScanRequest, QuarantineReadRequest, ReconcileAction, ReconciliationClaim,
    ReconciliationRepositoryOutcome, ReleaseClaimRequest, RequestDeletion, ResolvedMedia,
    SafeMediaRead, ScanCommitOutcome, ScanMetadata, ScanPublication, ScanVerdict, ScannerError,
    Sha256Digest, StorageError,
};

const DELETE_RELOAD_ATTEMPTS: usize = 3;

/// Trusted server integration input for one already stored, untrusted object.
///
/// The object key must have been generated server-side by object storage or the upload workflow.
/// It is intentionally absent from [`RegisteredMedia`] and all public references.
#[derive(Clone)]
pub struct RegisterMediaRequest {
    /// Authenticated tenant owner.
    pub tenant_id: TenantId,
    /// Authenticated principal owner.
    pub owner_id: SubjectId,
    /// Server-generated object-storage key supplied by trusted composition.
    pub storage_key: ObjectKey,
    /// Broad media class.
    pub kind: MediaKind,
    /// Exact declared checksum, size, and MIME.
    pub expected: ExpectedMedia,
    /// Mandatory finite expiry.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for RegisterMediaRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterMediaRequest")
            .field("kind", &self.kind)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Credential-free registration result. New media is always quarantined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredMedia {
    /// Opaque public reference.
    pub reference: MediaReference,
    /// Initial lifecycle state, always [`MediaState::Quarantined`].
    pub state: MediaState,
}

/// Authenticated request targeting one opaque media reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessMediaRequest {
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Authenticated principal.
    pub actor_id: SubjectId,
    /// Opaque public media reference.
    pub reference: MediaReference,
}

/// Authenticated canonical LLM binary source admission request.
pub struct UseLlmSourceRequest {
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Authenticated principal.
    pub actor_id: SubjectId,
    /// Canonical provider-neutral source from `omnius-llm-core`.
    pub source: BinarySource,
}

impl fmt::Debug for UseLlmSourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UseLlmSourceRequest")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Media admitted for one LLM operation after inline bounds or stored lifecycle checks.
pub enum AdmittedLlmMedia {
    /// Small decoded inline bytes within the strict configured bound.
    Inline(Bytes),
    /// Independently authorized, clean, unexpired stored bytes.
    Stored(SafeMediaRead),
}

impl fmt::Debug for AdmittedLlmMedia {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(bytes) => formatter
                .debug_struct("AdmittedLlmMedia::Inline")
                .field("byte_count", &bytes.len())
                .finish_non_exhaustive(),
            Self::Stored(read) => formatter
                .debug_tuple("AdmittedLlmMedia::Stored")
                .field(read)
                .finish(),
        }
    }
}

/// Bounded reconciliation outcome counters with no tenant, principal, object, or content labels.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MediaReconcileSummary {
    /// Rows claimed in this pass.
    pub claimed: u16,
    /// Quarantined rows newly published clean.
    pub cleaned: u16,
    /// Quarantined rows rejected and scheduled for cleanup.
    pub rejected: u16,
    /// Rows for which expiry won the publication race.
    pub expired: u16,
    /// Rows whose idempotent storage deletion was published.
    pub deleted: u16,
    /// Retryable effects released back to the durable queue.
    pub retried: u16,
    /// Stale or duplicate fenced publications safely ignored.
    pub stale_or_duplicate: u16,
}

/// Bounded server-side media workflow over durable repository, storage, scanner, and authz ports.
#[derive(Clone)]
pub struct MediaWorkflow {
    repository: Arc<dyn MediaRepository>,
    storage: Arc<dyn crate::MediaStorage>,
    scanner: Arc<dyn MediaScanner>,
    authorization: Arc<dyn MediaAuthorization>,
    policy: MediaPolicy,
}

impl MediaWorkflow {
    /// Creates a media workflow from typed ports and validated limits.
    #[must_use]
    pub fn new(
        repository: Arc<dyn MediaRepository>,
        storage: Arc<dyn crate::MediaStorage>,
        scanner: Arc<dyn MediaScanner>,
        authorization: Arc<dyn MediaAuthorization>,
        policy: MediaPolicy,
    ) -> Self {
        Self {
            repository,
            storage,
            scanner,
            authorization,
            policy,
        }
    }

    /// Registers authenticated uploaded media in quarantine under a server-generated identity.
    ///
    /// # Errors
    ///
    /// Returns a value-free validation or repository error. No clean availability is implied by a
    /// prior upload-workflow scan; this lifecycle publishes its own fenced result.
    pub async fn register_input(
        &self,
        request: RegisterMediaRequest,
    ) -> Result<RegisteredMedia, MediaError> {
        self.register(request, MediaOrigin::UserUpload).await
    }

    /// Registers provider-produced media in quarantine under a server-generated identity.
    ///
    /// # Errors
    ///
    /// Returns a value-free validation or repository error. Provider origin never bypasses scanning.
    pub async fn register_provider_output(
        &self,
        request: RegisterMediaRequest,
    ) -> Result<RegisteredMedia, MediaError> {
        self.register(request, MediaOrigin::ProviderOutput).await
    }

    /// Resolves clean, unexpired media metadata after a dedicated authorization decision.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Unauthorized`], [`MediaError::Expired`], or a value-free unavailable
    /// error without revealing storage coordinates.
    pub async fn resolve(&self, request: AccessMediaRequest) -> Result<ResolvedMedia, MediaError> {
        let media = self.load_authorized(request, MediaAction::Resolve).await?;
        self.ensure_current(&media, OffsetDateTime::now_utc())
            .await?;
        if media.state() != MediaState::Clean {
            return Err(MediaError::Unavailable(media.state()));
        }
        Ok(ResolvedMedia {
            reference: media.public_reference(),
            kind: media.kind(),
            size_bytes: media.expected().size_bytes(),
            mime: media.expected().mime().clone(),
            expires_at: media.expires_at(),
        })
    }

    /// Opens clean, unexpired bytes after a dedicated use authorization decision.
    ///
    /// # Errors
    ///
    /// Fails closed for quarantine, rejection, expiry, deletion, authorization, and storage errors.
    pub async fn use_media(
        &self,
        request: AccessMediaRequest,
    ) -> Result<SafeMediaRead, MediaError> {
        let media = self.load_authorized(request, MediaAction::Use).await?;
        self.ensure_current(&media, OffsetDateTime::now_utc())
            .await?;
        if media.state() != MediaState::Clean {
            return Err(MediaError::Unavailable(media.state()));
        }
        let expected = media.expected();
        let body = self
            .storage
            .open_clean(CleanReadRequest {
                tenant_id: media.tenant_id(),
                object_key: media.storage_key().clone(),
                expected_size: expected.size_bytes(),
                expected_sha256: expected.sha256(),
                expires_at: media.expires_at(),
            })
            .await
            .map_err(map_storage_error)?;
        Ok(SafeMediaRead {
            kind: media.kind(),
            mime: expected.mime().clone(),
            size_bytes: expected.size_bytes(),
            body: expiring_stream(body, media.expires_at()),
        })
    }

    /// Admits one canonical LLM binary source.
    ///
    /// Small inline values are decoded only after a pre-allocation length bound. URLs are rejected.
    /// Object-source values are interpreted as opaque media IDs and pass through [`Self::use_media`].
    ///
    /// # Errors
    ///
    /// Returns value-free source, size, encoding, authorization, lifecycle, or storage errors.
    pub async fn use_llm_source(
        &self,
        request: UseLlmSourceRequest,
    ) -> Result<AdmittedLlmMedia, MediaError> {
        match request.source {
            BinarySource::Inline(inline) => {
                let encoded = inline.data_base64();
                let max_encoded = self
                    .policy
                    .max_inline_bytes()
                    .checked_add(2)
                    .and_then(|value| value.checked_div(3))
                    .and_then(|value| value.checked_mul(4))
                    .ok_or(MediaError::InvalidPolicy)?;
                if encoded.len() > max_encoded {
                    return Err(MediaError::InlineTooLarge);
                }
                let bytes = STANDARD
                    .decode(encoded)
                    .map_err(|_| MediaError::InvalidInlineEncoding)?;
                if bytes.len() > self.policy.max_inline_bytes() {
                    return Err(MediaError::InlineTooLarge);
                }
                Ok(AdmittedLlmMedia::Inline(Bytes::from(bytes)))
            }
            BinarySource::Object(object) => {
                let media_id = object
                    .object_key()
                    .parse::<MediaId>()
                    .map_err(|_| MediaError::InvalidReference)?;
                let read = self
                    .use_media(AccessMediaRequest {
                        tenant_id: request.tenant_id,
                        actor_id: request.actor_id,
                        reference: MediaReference::new(media_id),
                    })
                    .await?;
                Ok(AdmittedLlmMedia::Stored(read))
            }
            BinarySource::Url(_) => Err(MediaError::ExternalUrlForbidden),
            _ => Err(MediaError::UnsupportedSource),
        }
    }

    /// Independently authorizes and idempotently schedules deletion.
    ///
    /// # Errors
    ///
    /// Returns value-free lookup, authorization, or repository errors. Stale transition races are
    /// reloaded a bounded number of times.
    pub async fn delete(&self, request: AccessMediaRequest) -> Result<DeleteResult, MediaError> {
        let mut media = self.load_authorized(request, MediaAction::Delete).await?;
        for _ in 0..DELETE_RELOAD_ATTEMPTS {
            let outcome = self
                .repository
                .request_deletion(RequestDeletion {
                    tenant_id: media.tenant_id(),
                    media_id: media.id(),
                    expected_revision: media.revision(),
                    cause: DeleteCause::OwnerRequest,
                    now: OffsetDateTime::now_utc(),
                })
                .await?;
            match outcome {
                DeleteRequestOutcome::Scheduled => return Ok(DeleteResult::Scheduled),
                DeleteRequestOutcome::AlreadyScheduled => {
                    return Ok(DeleteResult::AlreadyScheduled);
                }
                DeleteRequestOutcome::AlreadyDeleted => return Ok(DeleteResult::AlreadyDeleted),
                DeleteRequestOutcome::Stale => {
                    media = self
                        .repository
                        .find(request.tenant_id, request.reference.id())
                        .await?
                        .ok_or(MediaError::NotFound)?;
                    if media.owner_id() != request.actor_id {
                        return Err(MediaError::Unauthorized);
                    }
                }
            }
        }
        Err(MediaError::RepositoryUnavailable)
    }

    /// Claims and processes at most one configured reconciliation batch.
    ///
    /// Storage and scanner calls occur outside repository transactions. Retryable failures release
    /// their lease; all publications require the claimed revision/token, and deletion additionally
    /// requires the immutable deletion revision.
    ///
    /// # Errors
    ///
    /// Returns a value-free repository or policy error. Storage and scanner failures are reflected
    /// as released retry counts unless claim release itself fails.
    pub async fn reconcile_once(
        &self,
        now: OffsetDateTime,
    ) -> Result<MediaReconcileSummary, MediaError> {
        let lease_duration = time::Duration::try_from(self.policy.claim_lease())
            .map_err(|_| MediaError::InvalidPolicy)?;
        let lease_until = now
            .checked_add(lease_duration)
            .ok_or(MediaError::InvalidPolicy)?;
        let claims = self
            .repository
            .claim_reconciliation(ClaimReconciliationRequest {
                now,
                lease_until,
                limit: self.policy.reconcile_batch().get(),
            })
            .await?;
        if claims.len() > usize::from(self.policy.reconcile_batch().get()) {
            return Err(MediaError::CorruptRecord);
        }

        let mut summary = MediaReconcileSummary {
            claimed: u16::try_from(claims.len()).map_err(|_| MediaError::CorruptRecord)?,
            ..MediaReconcileSummary::default()
        };
        for claim in claims {
            if claim.transition.expected_revision != claim.media.revision() {
                return Err(MediaError::CorruptRecord);
            }
            match claim.action {
                ReconcileAction::Scan => self.reconcile_scan(claim, &mut summary).await?,
                ReconcileAction::Delete(fence) => {
                    self.reconcile_delete(claim, fence.deletion_revision, &mut summary)
                        .await?;
                }
            }
        }
        Ok(summary)
    }

    async fn register(
        &self,
        request: RegisterMediaRequest,
        origin: MediaOrigin,
    ) -> Result<RegisteredMedia, MediaError> {
        let now = OffsetDateTime::now_utc();
        let max_ttl = time::Duration::try_from(self.policy.max_ttl())
            .map_err(|_| MediaError::InvalidPolicy)?;
        let latest_expiry = now.checked_add(max_ttl).ok_or(MediaError::InvalidPolicy)?;
        if request.expires_at <= now || request.expires_at > latest_expiry {
            return Err(MediaError::InvalidExpiry);
        }
        if request.expected.size_bytes() > self.policy.max_media_bytes() {
            return Err(MediaError::InvalidSize);
        }

        let media = MediaObject::new_quarantined(
            MediaId::new(),
            request.tenant_id,
            request.owner_id,
            request.storage_key,
            origin,
            request.kind,
            request.expected,
            request.expires_at,
            now,
        );
        let reference = media.public_reference();
        self.repository.insert(media).await?;
        Ok(RegisteredMedia {
            reference,
            state: MediaState::Quarantined,
        })
    }

    async fn load_authorized(
        &self,
        request: AccessMediaRequest,
        action: MediaAction,
    ) -> Result<MediaObject, MediaError> {
        let media = self
            .repository
            .find(request.tenant_id, request.reference.id())
            .await?
            .ok_or(MediaError::NotFound)?;
        if media.owner_id() != request.actor_id {
            return Err(MediaError::Unauthorized);
        }
        self.authorization
            .authorize(AuthorizationRequest {
                action,
                tenant_id: request.tenant_id,
                actor_id: request.actor_id,
                media_id: media.id(),
                owner_id: media.owner_id(),
            })
            .await
            .map_err(|_| MediaError::Unauthorized)?;
        Ok(media)
    }

    async fn ensure_current(
        &self,
        media: &MediaObject,
        now: OffsetDateTime,
    ) -> Result<(), MediaError> {
        if media.expires_at() > now {
            return Ok(());
        }
        self.repository
            .request_deletion(RequestDeletion {
                tenant_id: media.tenant_id(),
                media_id: media.id(),
                expected_revision: media.revision(),
                cause: DeleteCause::Expired,
                now,
            })
            .await?;
        Err(MediaError::Expired)
    }

    async fn reconcile_scan(
        &self,
        claim: ReconciliationClaim,
        summary: &mut MediaReconcileSummary,
    ) -> Result<(), MediaError> {
        if claim.media.state() != MediaState::Quarantined
            || claim.media.deletion_revision().is_some()
        {
            return Err(MediaError::CorruptRecord);
        }
        let expected = claim.media.expected();
        let stream = match self
            .storage
            .open_quarantined(QuarantineReadRequest {
                tenant_id: claim.media.tenant_id(),
                object_key: claim.media.storage_key().clone(),
                max_bytes: self.policy.max_media_bytes(),
            })
            .await
        {
            Ok(stream) => stream,
            Err(StorageError::NotFound) => {
                return self
                    .publish_scan(
                        &claim,
                        ScanPublication::Rejected(MediaRejection::MissingObject),
                        summary,
                    )
                    .await;
            }
            Err(StorageError::Permanent) => {
                return self
                    .publish_scan(
                        &claim,
                        ScanPublication::Rejected(MediaRejection::StorageFailure),
                        summary,
                    )
                    .await;
            }
            Err(StorageError::Expired | StorageError::Retryable) => {
                return self.release_retry(&claim, summary).await;
            }
        };
        let scanner = match self
            .scanner
            .start(ScanMetadata {
                media_id: claim.media.id(),
                kind: claim.media.kind(),
                expected_size: expected.size_bytes(),
                expected_sha256: expected.sha256(),
                expected_mime: expected.mime().clone(),
            })
            .await
        {
            Ok(scanner) => scanner,
            Err(ScannerError::Retryable) => return self.release_retry(&claim, summary).await,
            Err(ScannerError::Permanent) => {
                return self
                    .publish_scan(
                        &claim,
                        ScanPublication::Rejected(MediaRejection::ScannerFailure),
                        summary,
                    )
                    .await;
            }
        };
        self.verify_stream(claim, stream, scanner, summary).await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the streaming verifier keeps bounded reads, hashing, scanning, and fail-closed publication contiguous"
    )]
    async fn verify_stream(
        &self,
        claim: ReconciliationClaim,
        mut stream: crate::MediaByteStream,
        mut scanner: Box<dyn crate::ScannerSession>,
        summary: &mut MediaReconcileSummary,
    ) -> Result<(), MediaError> {
        let mut size = 0_u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(StorageError::NotFound) => {
                    return self
                        .publish_scan(
                            &claim,
                            ScanPublication::Rejected(MediaRejection::MissingObject),
                            summary,
                        )
                        .await;
                }
                Err(StorageError::Permanent) => {
                    return self
                        .publish_scan(
                            &claim,
                            ScanPublication::Rejected(MediaRejection::StorageFailure),
                            summary,
                        )
                        .await;
                }
                Err(StorageError::Expired | StorageError::Retryable) => {
                    return self.release_retry(&claim, summary).await;
                }
            };
            if chunk.is_empty() {
                continue;
            }
            size = match size
                .checked_add(u64::try_from(chunk.len()).map_err(|_| MediaError::CorruptRecord)?)
            {
                Some(value) => value,
                None => {
                    return self
                        .publish_scan(
                            &claim,
                            ScanPublication::Rejected(MediaRejection::SizeMismatch),
                            summary,
                        )
                        .await;
                }
            };
            if size > claim.media.expected().size_bytes() || size > self.policy.max_media_bytes() {
                return self
                    .publish_scan(
                        &claim,
                        ScanPublication::Rejected(MediaRejection::SizeMismatch),
                        summary,
                    )
                    .await;
            }
            digest.update(&chunk);
            match scanner.scan_chunk(chunk).await {
                Ok(()) => {}
                Err(ScannerError::Retryable) => return self.release_retry(&claim, summary).await,
                Err(ScannerError::Permanent) => {
                    return self
                        .publish_scan(
                            &claim,
                            ScanPublication::Rejected(MediaRejection::ScannerFailure),
                            summary,
                        )
                        .await;
                }
            }
        }

        if size != claim.media.expected().size_bytes() {
            return self
                .publish_scan(
                    &claim,
                    ScanPublication::Rejected(MediaRejection::SizeMismatch),
                    summary,
                )
                .await;
        }
        let observed_digest = Sha256Digest::from_bytes(digest.finalize().into());
        if observed_digest != claim.media.expected().sha256() {
            return self
                .publish_scan(
                    &claim,
                    ScanPublication::Rejected(MediaRejection::ChecksumMismatch),
                    summary,
                )
                .await;
        }
        let report = match scanner.finish().await {
            Ok(report) => report,
            Err(ScannerError::Retryable) => return self.release_retry(&claim, summary).await,
            Err(ScannerError::Permanent) => {
                return self
                    .publish_scan(
                        &claim,
                        ScanPublication::Rejected(MediaRejection::ScannerFailure),
                        summary,
                    )
                    .await;
            }
        };
        let publication = if report.detected_mime == *claim.media.expected().mime() {
            match report.verdict {
                ScanVerdict::Clean => ScanPublication::Clean,
                ScanVerdict::Rejected => ScanPublication::Rejected(MediaRejection::ScanRejected),
            }
        } else {
            ScanPublication::Rejected(MediaRejection::MimeMismatch)
        };
        self.publish_scan(&claim, publication, summary).await
    }

    async fn publish_scan(
        &self,
        claim: &ReconciliationClaim,
        publication: ScanPublication,
        summary: &mut MediaReconcileSummary,
    ) -> Result<(), MediaError> {
        let outcome = self
            .repository
            .publish_scan(PublishScanRequest {
                tenant_id: claim.media.tenant_id(),
                media_id: claim.media.id(),
                expected_revision: claim.transition.expected_revision,
                claim_token: claim.transition.claim_token,
                publication,
                observed_at: OffsetDateTime::now_utc(),
            })
            .await?;
        match outcome {
            ScanCommitOutcome::PublishedClean => summary.cleaned += 1,
            ScanCommitOutcome::PublishedRejected => summary.rejected += 1,
            ScanCommitOutcome::Expired => summary.expired += 1,
            ScanCommitOutcome::Stale | ScanCommitOutcome::AlreadyApplied => {
                summary.stale_or_duplicate += 1;
            }
        }
        Ok(())
    }

    async fn reconcile_delete(
        &self,
        claim: ReconciliationClaim,
        deletion_revision: crate::DeletionRevision,
        summary: &mut MediaReconcileSummary,
    ) -> Result<(), MediaError> {
        if claim.media.deletion_revision() != Some(deletion_revision)
            || !matches!(
                claim.media.state(),
                MediaState::Rejected | MediaState::DeletionPending
            )
        {
            return Err(MediaError::CorruptRecord);
        }
        if self
            .storage
            .delete(DeleteObjectRequest {
                tenant_id: claim.media.tenant_id(),
                object_key: claim.media.storage_key().clone(),
                deletion_revision,
            })
            .await
            .is_err()
        {
            return self.release_retry(&claim, summary).await;
        }
        let outcome = self
            .repository
            .complete_deletion(CompleteDeletionRequest {
                tenant_id: claim.media.tenant_id(),
                media_id: claim.media.id(),
                expected_revision: claim.transition.expected_revision,
                claim_token: claim.transition.claim_token,
                deletion_revision,
                observed_at: OffsetDateTime::now_utc(),
            })
            .await?;
        match outcome {
            ReconciliationRepositoryOutcome::Applied => summary.deleted += 1,
            ReconciliationRepositoryOutcome::Stale
            | ReconciliationRepositoryOutcome::AlreadyApplied => {
                summary.stale_or_duplicate += 1;
            }
        }
        Ok(())
    }

    async fn release_retry(
        &self,
        claim: &ReconciliationClaim,
        summary: &mut MediaReconcileSummary,
    ) -> Result<(), MediaError> {
        let outcome = self
            .repository
            .release_claim(ReleaseClaimRequest {
                tenant_id: claim.media.tenant_id(),
                media_id: claim.media.id(),
                expected_revision: claim.transition.expected_revision,
                claim_token: claim.transition.claim_token,
            })
            .await?;
        match outcome {
            ReconciliationRepositoryOutcome::Applied => summary.retried += 1,
            ReconciliationRepositoryOutcome::Stale
            | ReconciliationRepositoryOutcome::AlreadyApplied => {
                summary.stale_or_duplicate += 1;
            }
        }
        Ok(())
    }
}

struct ExpiringStream {
    inner: crate::MediaByteStream,
    expires_at: OffsetDateTime,
    expired: bool,
}

impl Stream for ExpiringStream {
    type Item = Result<Bytes, StorageError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.expired {
            return Poll::Ready(None);
        }
        if OffsetDateTime::now_utc() >= self.expires_at {
            self.expired = true;
            return Poll::Ready(Some(Err(StorageError::Expired)));
        }
        let polled = self.inner.as_mut().poll_next(context);
        if matches!(&polled, Poll::Ready(Some(Ok(_))))
            && OffsetDateTime::now_utc() >= self.expires_at
        {
            self.expired = true;
            Poll::Ready(Some(Err(StorageError::Expired)))
        } else {
            polled
        }
    }
}

pub(crate) fn expiring_stream(
    inner: crate::MediaByteStream,
    expires_at: OffsetDateTime,
) -> crate::MediaByteStream {
    Box::pin(ExpiringStream {
        inner,
        expires_at,
        expired: false,
    })
}

fn map_storage_error(error: StorageError) -> MediaError {
    match error {
        StorageError::Expired => MediaError::Expired,
        StorageError::NotFound | StorageError::Retryable | StorageError::Permanent => {
            MediaError::StorageUnavailable
        }
    }
}
