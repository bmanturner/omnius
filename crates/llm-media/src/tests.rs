#![expect(
    clippy::unwrap_used,
    reason = "test fixtures keep invariant-construction failures at their exact setup site"
)]

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures::{StreamExt as _, future::BoxFuture, stream};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_llm_core::BinarySource;
use omnius_object_storage::ObjectKey;
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};

use crate::{
    AccessMediaRequest, AdmittedLlmMedia, AuthorizationError, AuthorizationRequest,
    ClaimReconciliationRequest, ClaimToken, CleanReadRequest, CompleteDeletionRequest, DeleteFence,
    DeleteObjectOutcome, DeleteObjectRequest, DeleteRequestOutcome, DeletionRevision,
    ExpectedMedia, MediaAction, MediaAuthorization, MediaByteStream, MediaError, MediaId,
    MediaKind, MediaMime, MediaObject, MediaOrigin, MediaPolicy, MediaRejection, MediaRepository,
    MediaScanner, MediaState, MediaStorage, MediaWorkflow, PersistedMediaObject,
    PublishScanRequest, QuarantineReadRequest, ReconcileAction, ReconciliationClaim,
    ReconciliationRepositoryOutcome, RegisterMediaRequest, ReleaseClaimRequest, RequestDeletion,
    ScanCommitOutcome, ScanMetadata, ScanPublication, ScanReport, ScanVerdict, ScannerError,
    ScannerSession, Sha256Digest, StorageError, TransitionFence, UseLlmSourceRequest,
};

type RowKey = (TenantId, MediaId);
type ObjectRowKey = (TenantId, String);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PublishRace {
    #[default]
    None,
    Delete,
    Expire,
}

#[derive(Default)]
struct RepositoryState {
    rows: HashMap<RowKey, MediaObject>,
    claims: HashMap<RowKey, (ClaimToken, OffsetDateTime)>,
    publish_race: PublishRace,
}

#[derive(Default)]
struct InMemoryRepository {
    state: Mutex<RepositoryState>,
}

impl InMemoryRepository {
    fn row(&self, tenant_id: TenantId, media_id: MediaId) -> MediaObject {
        lock(&self.state)
            .rows
            .get(&(tenant_id, media_id))
            .cloned()
            .unwrap()
    }

    fn set_publish_race(&self, race: PublishRace) {
        lock(&self.state).publish_race = race;
    }

    fn replace_row(state: &mut RepositoryState, fields: PersistedMediaObject) {
        let key = (fields.tenant_id, fields.id);
        state
            .rows
            .insert(key, MediaObject::restore(fields).unwrap());
    }

    fn schedule_deletion(
        state: &mut RepositoryState,
        key: RowKey,
        now: OffsetDateTime,
    ) -> DeleteRequestOutcome {
        let Some(current) = state.rows.get(&key).cloned() else {
            return DeleteRequestOutcome::Stale;
        };
        match current.state() {
            MediaState::Deleted => return DeleteRequestOutcome::AlreadyDeleted,
            MediaState::Rejected | MediaState::DeletionPending => {
                return DeleteRequestOutcome::AlreadyScheduled;
            }
            MediaState::Quarantined | MediaState::Clean => {}
        }
        let mut fields = current.into_persisted();
        fields.revision += 1;
        fields.state = MediaState::DeletionPending;
        fields.rejection = None;
        fields.deletion_revision = Some(DeletionRevision::new(fields.revision).unwrap());
        fields.updated_at = now;
        Self::replace_row(state, fields);
        state.claims.remove(&key);
        DeleteRequestOutcome::Scheduled
    }
}

impl MediaRepository for InMemoryRepository {
    fn insert(&self, media: MediaObject) -> BoxFuture<'_, Result<(), crate::RepositoryError>> {
        let result = {
            let mut state = lock(&self.state);
            let key = (media.tenant_id(), media.id());
            if state.rows.contains_key(&key)
                || state.rows.values().any(|row| {
                    row.tenant_id() == media.tenant_id()
                        && row.storage_key().as_str() == media.storage_key().as_str()
                })
            {
                Err(crate::RepositoryError::Conflict)
            } else {
                state.rows.insert(key, media);
                Ok(())
            }
        };
        Box::pin(async move { result })
    }

    fn find(
        &self,
        tenant_id: TenantId,
        media_id: MediaId,
    ) -> BoxFuture<'_, Result<Option<MediaObject>, crate::RepositoryError>> {
        let row = lock(&self.state).rows.get(&(tenant_id, media_id)).cloned();
        Box::pin(async move { Ok(row) })
    }

    fn request_deletion(
        &self,
        request: RequestDeletion,
    ) -> BoxFuture<'_, Result<DeleteRequestOutcome, crate::RepositoryError>> {
        let outcome = {
            let mut state = lock(&self.state);
            let key = (request.tenant_id, request.media_id);
            match state.rows.get(&key) {
                Some(row) if row.revision() == request.expected_revision => {
                    Self::schedule_deletion(&mut state, key, request.now)
                }
                Some(row) if row.state() == MediaState::Deleted => {
                    DeleteRequestOutcome::AlreadyDeleted
                }
                Some(row) if row.deletion_revision().is_some() => {
                    DeleteRequestOutcome::AlreadyScheduled
                }
                _ => DeleteRequestOutcome::Stale,
            }
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn claim_reconciliation(
        &self,
        request: ClaimReconciliationRequest,
    ) -> BoxFuture<'_, Result<Vec<ReconciliationClaim>, crate::RepositoryError>> {
        let claims = {
            let mut state = lock(&self.state);
            state
                .claims
                .retain(|_, (_, lease_until)| *lease_until > request.now);
            let keys = state.rows.keys().copied().collect::<Vec<_>>();
            for key in &keys {
                let expired = state.rows.get(key).is_some_and(|row| {
                    row.expires_at() <= request.now
                        && matches!(row.state(), MediaState::Quarantined | MediaState::Clean)
                });
                if expired {
                    Self::schedule_deletion(&mut state, *key, request.now);
                }
            }
            let mut claimed = Vec::new();
            for key in keys {
                if claimed.len() >= usize::from(request.limit) || state.claims.contains_key(&key) {
                    continue;
                }
                let Some(media) = state.rows.get(&key).cloned() else {
                    continue;
                };
                let action = match media.state() {
                    MediaState::Quarantined => ReconcileAction::Scan,
                    MediaState::Rejected | MediaState::DeletionPending => {
                        let Some(deletion_revision) = media.deletion_revision() else {
                            continue;
                        };
                        ReconcileAction::Delete(DeleteFence { deletion_revision })
                    }
                    MediaState::Clean | MediaState::Deleted => continue,
                };
                let token = ClaimToken::new();
                state.claims.insert(key, (token, request.lease_until));
                claimed.push(ReconciliationClaim {
                    transition: TransitionFence {
                        expected_revision: media.revision(),
                        claim_token: token,
                    },
                    media,
                    action,
                });
            }
            claimed
        };
        Box::pin(async move { Ok(claims) })
    }

    fn publish_scan(
        &self,
        request: PublishScanRequest,
    ) -> BoxFuture<'_, Result<ScanCommitOutcome, crate::RepositoryError>> {
        let outcome = {
            let mut state = lock(&self.state);
            let key = (request.tenant_id, request.media_id);
            let race = std::mem::take(&mut state.publish_race);
            if race == PublishRace::Delete {
                Self::schedule_deletion(&mut state, key, request.observed_at);
            } else if race == PublishRace::Expire
                && let Some(current) = state.rows.get(&key).cloned()
            {
                let mut fields = current.into_persisted();
                fields.expires_at = fields.created_at + Duration::NANOSECOND;
                Self::replace_row(&mut state, fields);
            }

            let Some(current) = state.rows.get(&key).cloned() else {
                return Box::pin(async { Ok(ScanCommitOutcome::Stale) });
            };
            if current.state() == MediaState::Clean && request.publication == ScanPublication::Clean
            {
                ScanCommitOutcome::AlreadyApplied
            } else if state.claims.get(&key).map(|(token, _)| token) != Some(&request.claim_token)
                || current.revision() != request.expected_revision
                || current.state() != MediaState::Quarantined
            {
                ScanCommitOutcome::Stale
            } else if current.expires_at() <= request.observed_at {
                Self::schedule_deletion(&mut state, key, request.observed_at);
                ScanCommitOutcome::Expired
            } else {
                let mut fields = current.into_persisted();
                fields.revision += 1;
                fields.updated_at = request.observed_at;
                match request.publication {
                    ScanPublication::Clean => {
                        fields.state = MediaState::Clean;
                        fields.rejection = None;
                        fields.deletion_revision = None;
                    }
                    ScanPublication::Rejected(reason) => {
                        fields.state = MediaState::Rejected;
                        fields.rejection = Some(reason);
                        fields.deletion_revision =
                            Some(DeletionRevision::new(fields.revision).unwrap());
                    }
                }
                Self::replace_row(&mut state, fields);
                state.claims.remove(&key);
                match request.publication {
                    ScanPublication::Clean => ScanCommitOutcome::PublishedClean,
                    ScanPublication::Rejected(_) => ScanCommitOutcome::PublishedRejected,
                }
            }
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn complete_deletion(
        &self,
        request: CompleteDeletionRequest,
    ) -> BoxFuture<'_, Result<ReconciliationRepositoryOutcome, crate::RepositoryError>> {
        let outcome = {
            let mut state = lock(&self.state);
            let key = (request.tenant_id, request.media_id);
            let Some(current) = state.rows.get(&key).cloned() else {
                return Box::pin(async { Ok(ReconciliationRepositoryOutcome::Stale) });
            };
            if current.state() == MediaState::Deleted
                && current.deletion_revision() == Some(request.deletion_revision)
            {
                ReconciliationRepositoryOutcome::AlreadyApplied
            } else if state.claims.get(&key).map(|(token, _)| token) != Some(&request.claim_token)
                || current.revision() != request.expected_revision
                || current.deletion_revision() != Some(request.deletion_revision)
            {
                ReconciliationRepositoryOutcome::Stale
            } else {
                let mut fields = current.into_persisted();
                fields.revision += 1;
                fields.state = MediaState::Deleted;
                fields.updated_at = request.observed_at;
                Self::replace_row(&mut state, fields);
                state.claims.remove(&key);
                ReconciliationRepositoryOutcome::Applied
            }
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn release_claim(
        &self,
        request: ReleaseClaimRequest,
    ) -> BoxFuture<'_, Result<ReconciliationRepositoryOutcome, crate::RepositoryError>> {
        let outcome = {
            let mut state = lock(&self.state);
            let key = (request.tenant_id, request.media_id);
            let matches = state.rows.get(&key).is_some_and(|row| {
                row.revision() == request.expected_revision
                    && state.claims.get(&key).map(|(token, _)| token) == Some(&request.claim_token)
            });
            if matches {
                state.claims.remove(&key);
                ReconciliationRepositoryOutcome::Applied
            } else {
                ReconciliationRepositoryOutcome::Stale
            }
        };
        Box::pin(async move { Ok(outcome) })
    }
}

#[derive(Default)]
struct InMemoryStorage {
    objects: Mutex<HashMap<ObjectRowKey, Vec<u8>>>,
    delete_calls: AtomicUsize,
    clean_open_calls: AtomicUsize,
    deletion_revisions: Mutex<Vec<DeletionRevision>>,
}

impl InMemoryStorage {
    fn insert(&self, tenant_id: TenantId, object_key: &ObjectKey, bytes: &[u8]) {
        lock(&self.objects).insert((tenant_id, object_key.as_str().to_owned()), bytes.to_vec());
    }

    fn delete_calls(&self) -> usize {
        self.delete_calls.load(Ordering::Relaxed)
    }

    fn clean_open_calls(&self) -> usize {
        self.clean_open_calls.load(Ordering::Relaxed)
    }

    fn deletion_revisions(&self) -> Vec<DeletionRevision> {
        lock(&self.deletion_revisions).clone()
    }

    fn stream(bytes: Vec<u8>) -> MediaByteStream {
        Box::pin(stream::iter([Ok(Bytes::from(bytes))]))
    }
}

impl MediaStorage for InMemoryStorage {
    fn open_quarantined(
        &self,
        request: QuarantineReadRequest,
    ) -> BoxFuture<'_, Result<MediaByteStream, StorageError>> {
        let bytes = lock(&self.objects)
            .get(&(request.tenant_id, request.object_key.as_str().to_owned()))
            .cloned();
        Box::pin(async move { bytes.map(Self::stream).ok_or(StorageError::NotFound) })
    }

    fn open_clean(
        &self,
        request: CleanReadRequest,
    ) -> BoxFuture<'_, Result<MediaByteStream, StorageError>> {
        self.clean_open_calls.fetch_add(1, Ordering::Relaxed);
        let bytes = lock(&self.objects)
            .get(&(request.tenant_id, request.object_key.as_str().to_owned()))
            .cloned();
        Box::pin(async move {
            let bytes = bytes.ok_or(StorageError::NotFound)?;
            if OffsetDateTime::now_utc() >= request.expires_at {
                return Err(StorageError::Expired);
            }
            if u64::try_from(bytes.len()).ok() != Some(request.expected_size)
                || digest(&bytes) != request.expected_sha256
            {
                return Err(StorageError::Permanent);
            }
            Ok(Self::stream(bytes))
        })
    }

    fn delete(
        &self,
        request: DeleteObjectRequest,
    ) -> BoxFuture<'_, Result<DeleteObjectOutcome, StorageError>> {
        self.delete_calls.fetch_add(1, Ordering::Relaxed);
        lock(&self.deletion_revisions).push(request.deletion_revision);
        let removed = lock(&self.objects)
            .remove(&(request.tenant_id, request.object_key.as_str().to_owned()))
            .is_some();
        Box::pin(async move {
            Ok(if removed {
                DeleteObjectOutcome::Deleted
            } else {
                DeleteObjectOutcome::NotFound
            })
        })
    }
}

struct StaticScanner {
    report: Mutex<ScanReport>,
}

impl StaticScanner {
    fn new(mime: MediaMime, verdict: ScanVerdict) -> Self {
        Self {
            report: Mutex::new(ScanReport {
                verdict,
                detected_mime: mime,
            }),
        }
    }

    fn set_report(&self, mime: MediaMime, verdict: ScanVerdict) {
        *lock(&self.report) = ScanReport {
            verdict,
            detected_mime: mime,
        };
    }
}

struct StaticScannerSession {
    report: ScanReport,
}

impl ScannerSession for StaticScannerSession {
    fn scan_chunk(&mut self, _chunk: Bytes) -> BoxFuture<'_, Result<(), ScannerError>> {
        Box::pin(async { Ok(()) })
    }

    fn finish(&mut self) -> BoxFuture<'_, Result<ScanReport, ScannerError>> {
        let report = self.report.clone();
        Box::pin(async move { Ok(report) })
    }
}

impl MediaScanner for StaticScanner {
    fn start(
        &self,
        _metadata: ScanMetadata,
    ) -> BoxFuture<'_, Result<Box<dyn ScannerSession>, ScannerError>> {
        let session = StaticScannerSession {
            report: lock(&self.report).clone(),
        };
        Box::pin(async move { Ok(Box::new(session) as Box<dyn ScannerSession>) })
    }
}

#[derive(Default)]
struct RecordingAuthorization {
    calls: Mutex<Vec<MediaAction>>,
    denied: Mutex<Option<MediaAction>>,
}

impl RecordingAuthorization {
    fn calls(&self) -> Vec<MediaAction> {
        lock(&self.calls).clone()
    }

    fn deny(&self, action: Option<MediaAction>) {
        *lock(&self.denied) = action;
    }
}

impl MediaAuthorization for RecordingAuthorization {
    fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> BoxFuture<'_, Result<(), AuthorizationError>> {
        lock(&self.calls).push(request.action);
        let result = if *lock(&self.denied) == Some(request.action) {
            Err(AuthorizationError::Denied)
        } else {
            Ok(())
        };
        Box::pin(async move { result })
    }
}

struct Harness {
    tenant_id: TenantId,
    owner_id: SubjectId,
    other_tenant: TenantId,
    other_principal: SubjectId,
    repository: Arc<InMemoryRepository>,
    storage: Arc<InMemoryStorage>,
    scanner: Arc<StaticScanner>,
    authorization: Arc<RecordingAuthorization>,
    workflow: MediaWorkflow,
}

impl Harness {
    fn new() -> Self {
        let repository = Arc::new(InMemoryRepository::default());
        let storage = Arc::new(InMemoryStorage::default());
        let scanner = Arc::new(StaticScanner::new(mime("image/png"), ScanVerdict::Clean));
        let authorization = Arc::new(RecordingAuthorization::default());
        let workflow = MediaWorkflow::new(
            repository.clone(),
            storage.clone(),
            scanner.clone(),
            authorization.clone(),
            MediaPolicy::default(),
        );
        Self {
            tenant_id: TenantId::new(),
            owner_id: SubjectId::new(),
            other_tenant: TenantId::new(),
            other_principal: SubjectId::new(),
            repository,
            storage,
            scanner,
            authorization,
            workflow,
        }
    }

    async fn register(
        &self,
        bytes: &[u8],
        expected_size: u64,
        expected_digest: Sha256Digest,
        expected_mime: MediaMime,
        provider_output: bool,
    ) -> (crate::RegisteredMedia, ObjectKey) {
        let key = ObjectKey::new();
        self.storage.insert(self.tenant_id, &key, bytes);
        let request = RegisterMediaRequest {
            tenant_id: self.tenant_id,
            owner_id: self.owner_id,
            storage_key: key.clone(),
            kind: MediaKind::Image,
            expected: ExpectedMedia::new(
                expected_size,
                expected_digest,
                expected_mime,
                &MediaPolicy::default(),
            )
            .unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::HOUR,
        };
        let registered = if provider_output {
            self.workflow
                .register_provider_output(request)
                .await
                .unwrap()
        } else {
            self.workflow.register_input(request).await.unwrap()
        };
        (registered, key)
    }

    fn access(&self, reference: crate::MediaReference) -> AccessMediaRequest {
        AccessMediaRequest {
            tenant_id: self.tenant_id,
            actor_id: self.owner_id,
            reference,
        }
    }
}

fn mime(value: &str) -> MediaMime {
    MediaMime::parse(value).unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[test]
fn media_identifiers_reject_noncanonical_uuid_encodings() {
    let media_id = MediaId::new();
    let simple = media_id.to_string().replace('-', "");
    let uppercase = media_id.to_string().to_ascii_uppercase();

    assert_eq!(
        simple.parse::<MediaId>(),
        Err(crate::MediaIdError::InvalidUuid)
    );
    assert_eq!(
        uppercase.parse::<MediaId>(),
        Err(crate::MediaIdError::InvalidUuid)
    );
    assert!(serde_json::from_str::<MediaId>(&format!("\"{simple}\"")).is_err());
}

#[tokio::test]
async fn clean_stream_stops_at_the_expiry_fence() {
    let mut body = crate::workflow::expiring_stream(
        InMemoryStorage::stream(b"must not escape".to_vec()),
        OffsetDateTime::now_utc() - Duration::NANOSECOND,
    );

    assert_eq!(body.next().await, Some(Err(StorageError::Expired)));
    assert!(body.next().await.is_none());
}

#[tokio::test]
async fn cross_tenant_and_principal_access_is_denied() {
    let harness = Harness::new();
    let bytes = b"\x89PNG\r\n\x1a\nmedia";
    let (registered, _) = harness
        .register(
            bytes,
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/png"),
            false,
        )
        .await;

    let cross_tenant = harness
        .workflow
        .resolve(AccessMediaRequest {
            tenant_id: harness.other_tenant,
            actor_id: harness.owner_id,
            reference: registered.reference,
        })
        .await;
    let cross_principal = harness
        .workflow
        .delete(AccessMediaRequest {
            tenant_id: harness.tenant_id,
            actor_id: harness.other_principal,
            reference: registered.reference,
        })
        .await;

    assert_eq!(cross_tenant.unwrap_err(), MediaError::NotFound);
    assert_eq!(cross_principal.unwrap_err(), MediaError::Unauthorized);
}

#[tokio::test]
async fn checksum_size_and_mime_mismatches_fail_closed() {
    let bytes = b"\x89PNG\r\n\x1a\nmedia";
    let cases = [
        (
            u64::try_from(bytes.len()).unwrap() + 1,
            digest(bytes),
            mime("image/png"),
            MediaRejection::SizeMismatch,
        ),
        (
            u64::try_from(bytes.len()).unwrap(),
            Sha256Digest::from_bytes([0; 32]),
            mime("image/png"),
            MediaRejection::ChecksumMismatch,
        ),
        (
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/jpeg"),
            MediaRejection::MimeMismatch,
        ),
    ];

    for (size, expected_digest, expected_mime, rejection) in cases {
        let harness = Harness::new();
        let (registered, _) = harness
            .register(bytes, size, expected_digest, expected_mime, false)
            .await;
        harness
            .workflow
            .reconcile_once(OffsetDateTime::now_utc())
            .await
            .unwrap();
        let row = harness
            .repository
            .row(harness.tenant_id, registered.reference.id());
        assert_eq!(
            (row.state(), row.rejection()),
            (MediaState::Rejected, Some(rejection))
        );
    }
}

#[tokio::test]
async fn provider_output_and_rejected_scans_are_never_usable() {
    let harness = Harness::new();
    harness
        .scanner
        .set_report(mime("image/png"), ScanVerdict::Rejected);
    let bytes = b"\x89PNG\r\n\x1a\nprovider";
    let (registered, _) = harness
        .register(
            bytes,
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/png"),
            true,
        )
        .await;
    let initial = harness
        .repository
        .row(harness.tenant_id, registered.reference.id());
    let quarantined_use = harness
        .workflow
        .use_media(harness.access(registered.reference))
        .await;

    harness
        .workflow
        .reconcile_once(OffsetDateTime::now_utc())
        .await
        .unwrap();
    let rejected = harness
        .repository
        .row(harness.tenant_id, registered.reference.id());
    let rejected_use = harness
        .workflow
        .use_media(harness.access(registered.reference))
        .await;

    assert_eq!(
        (initial.origin(), initial.state()),
        (MediaOrigin::ProviderOutput, MediaState::Quarantined)
    );
    assert_eq!(
        quarantined_use.unwrap_err(),
        MediaError::Unavailable(MediaState::Quarantined)
    );
    assert_eq!(
        (rejected.state(), rejected.rejection()),
        (MediaState::Rejected, Some(MediaRejection::ScanRejected))
    );
    assert_eq!(
        rejected_use.unwrap_err(),
        MediaError::Unavailable(MediaState::Rejected)
    );
}

#[tokio::test]
async fn expiry_and_delete_races_cannot_publish_clean_media() {
    for race in [PublishRace::Expire, PublishRace::Delete] {
        let harness = Harness::new();
        let bytes = b"\x89PNG\r\n\x1a\nrace";
        let (registered, _) = harness
            .register(
                bytes,
                u64::try_from(bytes.len()).unwrap(),
                digest(bytes),
                mime("image/png"),
                true,
            )
            .await;
        harness.repository.set_publish_race(race);

        let summary = harness
            .workflow
            .reconcile_once(OffsetDateTime::now_utc())
            .await
            .unwrap();
        let row = harness
            .repository
            .row(harness.tenant_id, registered.reference.id());
        let use_result = harness
            .workflow
            .use_media(harness.access(registered.reference))
            .await;

        assert_ne!(row.state(), MediaState::Clean);
        assert!(summary.expired == 1 || summary.stale_or_duplicate == 1);
        assert!(use_result.is_err());
    }
}

#[tokio::test]
async fn reconciliation_reclaims_an_expired_worker_lease() {
    let harness = Harness::new();
    let bytes = b"\x89PNG\r\n\x1a\nlease";
    let (registered, _) = harness
        .register(
            bytes,
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/png"),
            true,
        )
        .await;
    let claimed_at = OffsetDateTime::now_utc();
    let abandoned = harness
        .repository
        .claim_reconciliation(ClaimReconciliationRequest {
            now: claimed_at,
            lease_until: claimed_at + Duration::SECOND,
            limit: 1,
        })
        .await
        .unwrap();

    let recovered = harness
        .workflow
        .reconcile_once(claimed_at + Duration::seconds(2))
        .await
        .unwrap();
    let row = harness
        .repository
        .row(harness.tenant_id, registered.reference.id());

    assert_eq!(abandoned.len(), 1);
    assert_eq!(recovered.cleaned, 1);
    assert_eq!(row.state(), MediaState::Clean);
}

#[tokio::test]
async fn reconciliation_cleanup_is_idempotent() {
    let harness = Harness::new();
    harness
        .scanner
        .set_report(mime("image/png"), ScanVerdict::Rejected);
    let bytes = b"\x89PNG\r\n\x1a\ncleanup";
    let (registered, _) = harness
        .register(
            bytes,
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/png"),
            true,
        )
        .await;

    harness
        .workflow
        .reconcile_once(OffsetDateTime::now_utc())
        .await
        .unwrap();
    let first_cleanup = harness
        .workflow
        .reconcile_once(OffsetDateTime::now_utc())
        .await
        .unwrap();
    let duplicate_cleanup = harness
        .workflow
        .reconcile_once(OffsetDateTime::now_utc())
        .await
        .unwrap();
    let row = harness
        .repository
        .row(harness.tenant_id, registered.reference.id());

    assert_eq!(first_cleanup.deleted, 1);
    assert_eq!(duplicate_cleanup.claimed, 0);
    assert_eq!(harness.storage.delete_calls(), 1);
    assert_eq!(
        harness.storage.deletion_revisions(),
        vec![row.deletion_revision().unwrap()]
    );
    assert_eq!(row.state(), MediaState::Deleted);
}

#[tokio::test]
async fn resolve_use_and_delete_each_require_authorization() {
    let harness = Harness::new();
    let bytes = b"\x89PNG\r\n\x1a\nauthorized";
    let (registered, _) = harness
        .register(
            bytes,
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/png"),
            false,
        )
        .await;
    harness
        .workflow
        .reconcile_once(OffsetDateTime::now_utc())
        .await
        .unwrap();

    harness
        .workflow
        .resolve(harness.access(registered.reference))
        .await
        .unwrap();
    harness
        .workflow
        .use_media(harness.access(registered.reference))
        .await
        .unwrap();
    harness
        .workflow
        .delete(harness.access(registered.reference))
        .await
        .unwrap();

    assert_eq!(
        harness.authorization.calls(),
        vec![MediaAction::Resolve, MediaAction::Use, MediaAction::Delete]
    );
}

#[tokio::test]
async fn denied_authorization_blocks_every_media_action_before_side_effects() {
    let harness = Harness::new();
    let bytes = b"\x89PNG\r\n\x1a\ndenied";
    let (registered, _) = harness
        .register(
            bytes,
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("image/png"),
            false,
        )
        .await;
    harness
        .workflow
        .reconcile_once(OffsetDateTime::now_utc())
        .await
        .unwrap();

    for action in [MediaAction::Resolve, MediaAction::Use, MediaAction::Delete] {
        harness.authorization.deny(Some(action));
        let clean_reads_before = harness.storage.clean_open_calls();
        let error = match action {
            MediaAction::Resolve => harness
                .workflow
                .resolve(harness.access(registered.reference))
                .await
                .map(|_| ())
                .unwrap_err(),
            MediaAction::Use => harness
                .workflow
                .use_media(harness.access(registered.reference))
                .await
                .map(|_| ())
                .unwrap_err(),
            MediaAction::Delete => harness
                .workflow
                .delete(harness.access(registered.reference))
                .await
                .map(|_| ())
                .unwrap_err(),
        };
        let row = harness
            .repository
            .row(harness.tenant_id, registered.reference.id());

        assert_eq!(error, MediaError::Unauthorized);
        assert_eq!(harness.storage.clean_open_calls(), clean_reads_before);
        assert_eq!(harness.storage.delete_calls(), 0);
        assert_eq!(row.state(), MediaState::Clean);
    }
}

#[tokio::test]
async fn large_inline_and_external_url_sources_are_rejected() {
    let harness = Harness::new();
    let oversized = vec![7_u8; MediaPolicy::default().max_inline_bytes() + 1];
    let inline_result = harness
        .workflow
        .use_llm_source(UseLlmSourceRequest {
            tenant_id: harness.tenant_id,
            actor_id: harness.owner_id,
            source: BinarySource::inline(STANDARD.encode(oversized)).unwrap(),
        })
        .await;
    let url_result = harness
        .workflow
        .use_llm_source(UseLlmSourceRequest {
            tenant_id: harness.tenant_id,
            actor_id: harness.owner_id,
            source: BinarySource::url("https://credentials.invalid/media".to_owned()).unwrap(),
        })
        .await;

    assert!(matches!(inline_result, Err(MediaError::InlineTooLarge)));
    assert!(matches!(url_result, Err(MediaError::ExternalUrlForbidden)));
}

#[test]
fn public_references_and_debug_output_do_not_leak_storage_details() {
    let tenant_id = TenantId::new();
    let owner_id = SubjectId::new();
    let storage_key = ObjectKey::new();
    let storage_key_text = storage_key.as_str().to_owned();
    let bytes = b"secret media";
    let now = OffsetDateTime::now_utc();
    let media = MediaObject::new_quarantined(
        MediaId::new(),
        tenant_id,
        owner_id,
        storage_key.clone(),
        MediaOrigin::ProviderOutput,
        MediaKind::File,
        ExpectedMedia::new(
            u64::try_from(bytes.len()).unwrap(),
            digest(bytes),
            mime("application/octet-stream"),
            &MediaPolicy::default(),
        )
        .unwrap(),
        now + Duration::HOUR,
        now,
    );
    let reference_json = serde_json::to_string(&media.public_reference()).unwrap();
    let llm_source_json =
        serde_json::to_string(&media.public_reference().to_llm_source().unwrap()).unwrap();
    let request_debug = format!(
        "{:?}",
        RegisterMediaRequest {
            tenant_id,
            owner_id,
            storage_key,
            kind: MediaKind::File,
            expected: media.expected().clone(),
            expires_at: media.expires_at(),
        }
    );
    let object_debug = format!("{media:?}");

    for output in [reference_json, llm_source_json, request_debug, object_debug] {
        assert!(!output.contains(&storage_key_text));
        assert!(!output.contains("https://"));
        assert!(!output.contains("credential"));
        assert!(!output.contains("secret media"));
    }
}

#[tokio::test]
async fn small_inline_source_is_bounded_and_redacted() {
    let harness = Harness::new();
    let admitted = harness
        .workflow
        .use_llm_source(UseLlmSourceRequest {
            tenant_id: harness.tenant_id,
            actor_id: harness.owner_id,
            source: BinarySource::inline(STANDARD.encode(b"small")).unwrap(),
        })
        .await
        .unwrap();

    assert!(
        matches!(admitted, AdmittedLlmMedia::Inline(bytes) if bytes == Bytes::from_static(b"small"))
    );
}
