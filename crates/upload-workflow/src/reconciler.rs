use std::{sync::Arc, time::Duration};

use futures::StreamExt as _;
use metrics::counter;
use omnius_core::{ErrorCode, ServiceError};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, IdempotencyRequirement, Jitter, Job, JobPolicy,
};
use omnius_object_storage::{
    BlobStore, BlobStoreError, GetCondition, GetRequest, OperationContext, TransferRequest,
};
use omnius_runtime::{Criticality, HeartbeatPolicy, RestartPolicy, TaskSpec};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::{
    DeclaredMime, MalwareScanner, MimeInspector, PostgresUploadRepository, ReconcilerConfig,
    RejectionReason, ScanMetadata, ScanVerdict, ScannerFailure, Upload, UploadError, UploadId,
    UploadState, WorkFailureCode, WorkKind,
};

const RECONCILER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const RECONCILER_HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(20);

const RECONCILE_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Optional,
    10,
    1_000,
    60_000,
    2,
    Jitter::Full,
    300,
    16,
    Some(600),
    "uploads",
    5,
    604_800,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    256,
) {
    Ok(policy) => policy,
    Err(_) => panic!("upload reconciliation policy must be valid"),
};

/// At-least-once job trigger containing only a safe upload identifier. The durable PostgreSQL
/// reconciliation ledger, rather than delivery identity, fences all external effects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconcileUploadsJob {
    /// Upload whose durable work should be made promptly observable to a worker.
    pub upload_id: UploadId,
}

impl Job for ReconcileUploadsJob {
    const NAME: &'static str = "uploads.reconcile";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = RECONCILE_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_job_uploads_reconcile";
    const RUNBOOK: &'static str = "runbooks/uploads-reconcile";
}

/// Restartable, leased upload reconciler. It never holds PostgreSQL transactions across object or
/// scanner effects; every state publication is committed under the current `UUIDv7` lease fence.
#[derive(Clone)]
pub struct UploadReconciler {
    repository: PostgresUploadRepository,
    blob_store: BlobStore,
    scanner: Arc<dyn MalwareScanner>,
    config: ReconcilerConfig,
}

impl UploadReconciler {
    /// Constructs a reconciler after validating all bounds.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] for unsafe lease, timeout, retry, poll, or orphan bounds.
    pub fn new(
        repository: PostgresUploadRepository,
        blob_store: BlobStore,
        scanner: Arc<dyn MalwareScanner>,
        config: ReconcilerConfig,
    ) -> Result<Self, UploadError> {
        config.validate()?;
        Ok(Self {
            repository,
            blob_store,
            scanner,
            config,
        })
    }

    /// Claims one disjoint batch and starts every item immediately under a concurrency bound equal
    /// to the validated claim batch. Duplicate delivery simply races through the fenced claim.
    /// Cancellation is observed by every claimed future so all still-live fences are retried.
    ///
    /// # Errors
    ///
    /// Returns an error when cancellation is requested or claiming, processing, retrying, or
    /// persistence fails. Expected lease loss is nonfatal.
    pub async fn reconcile_once(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<usize, UploadError> {
        if cancellation.is_cancelled() {
            return Err(UploadError::Cancelled);
        }
        let work_items = self.repository.claim(&self.config).await?;
        let count = work_items.len();
        let outcomes = futures::stream::iter(
            work_items
                .into_iter()
                .map(|work| async move { self.process_claimed(work, cancellation).await }),
        )
        .buffer_unordered(usize::from(self.config.claim_batch))
        .collect::<Vec<_>>()
        .await;
        if let Some(error) = outcomes.iter().find_map(|outcome| match outcome {
            Err(error) if *error != UploadError::Cancelled => Some(*error),
            _ => None,
        }) {
            return Err(error);
        }
        if cancellation.is_cancelled() {
            return Err(UploadError::Cancelled);
        }
        Ok(count)
    }

    async fn process_claimed(
        &self,
        work: crate::LeasedWork,
        cancellation: &CancellationToken,
    ) -> Result<(), UploadError> {
        let child = cancellation.child_token();
        if cancellation.is_cancelled() {
            child.cancel();
            self.finalize_cancelled(&work).await?;
            return Err(UploadError::Cancelled);
        }
        let publication_started_at = if work.kind == WorkKind::Scan {
            match tokio::time::timeout(
                self.config.finalization_margin,
                self.repository
                    .begin_publication(&work, self.config.lease_duration),
            )
            .await
            {
                Ok(Ok(started_at)) => Some(started_at),
                Ok(Err(UploadError::LostLease)) => return Ok(()),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(UploadError::Timeout),
            }
        } else {
            None
        };
        let prepared = Self::prepare_effect(&work, publication_started_at)?;
        let effect = tokio::time::timeout(
            self.config.work_timeout,
            self.run_effect(&work, &prepared, &child),
        );
        tokio::pin!(effect);
        // An effect outcome is durable knowledge. Prefer it over simultaneous supervisor
        // cancellation, then spend only the separately reserved margin on fenced finalization.
        tokio::select! {
            biased;
            outcome = &mut effect => {
                if let Ok(outcome) = outcome {
                    self.finalize_with_margin(&work, outcome).await
                } else {
                    child.cancel();
                    self.finalize_with_margin(
                        &work,
                        EffectOutcome::Retry(WorkFailureCode::Timeout),
                    )
                    .await
                }
            }
            () = cancellation.cancelled() => {
                child.cancel();
                self.finalize_cancelled(&work).await?;
                Err(UploadError::Cancelled)
            }
        }
    }

    /// Builds a supervised degraded-capability task with heartbeats emitted throughout long work,
    /// bounded restart-on-failure, and drain handling that awaits release of every claimed fence.
    #[must_use]
    pub fn task_spec(&self) -> TaskSpec {
        let reconciler = self.clone();
        TaskSpec::new(
            "upload-reconciler",
            "upload-workflow",
            Criticality::Degraded,
            self.config
                .work_timeout
                .saturating_add(self.config.lease_duration),
            move |context| {
                let reconciler = reconciler.clone();
                async move {
                    let mut heartbeat = tokio::time::interval(RECONCILER_HEARTBEAT_INTERVAL);
                    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        context.heartbeat();
                        let cancellation = CancellationToken::new();
                        let reconciliation = reconciler.reconcile_once(&cancellation);
                        tokio::pin!(reconciliation);
                        let mut drain_requested = false;
                        let result = loop {
                            tokio::select! {
                                () = context.draining(), if !drain_requested => {
                                    drain_requested = true;
                                    cancellation.cancel();
                                }
                                _ = heartbeat.tick() => context.heartbeat(),
                                result = &mut reconciliation => break result,
                            }
                        };
                        match result {
                            Ok(_) => {}
                            Err(UploadError::Cancelled) if drain_requested => {}
                            Err(_) => return Err(task_error()),
                        }
                        context.heartbeat();
                        if drain_requested {
                            return Ok(());
                        }

                        let sleep = tokio::time::sleep(reconciler.config.poll_interval);
                        tokio::pin!(sleep);
                        loop {
                            tokio::select! {
                                () = context.draining() => return Ok(()),
                                _ = heartbeat.tick() => context.heartbeat(),
                                () = &mut sleep => break,
                            }
                        }
                    }
                }
            },
        )
        .with_heartbeat_policy(HeartbeatPolicy::Expected {
            stale_after: RECONCILER_HEARTBEAT_STALE_AFTER,
        })
        .with_restart_policy(RestartPolicy::on_failure(
            10,
            Duration::from_secs(1),
            Duration::from_secs(30),
            10,
        ))
    }

    fn prepare_effect(
        work: &crate::LeasedWork,
        publication_started_at: Option<OffsetDateTime>,
    ) -> Result<PreparedEffect<'_>, UploadError> {
        match work.kind {
            WorkKind::Delete => Ok(PreparedEffect::Delete),
            WorkKind::Verify | WorkKind::Scan => {
                let upload = work.upload_snapshot.as_ref().ok_or(UploadError::State)?;
                if Some(upload.id) != work.upload_id
                    || upload.tenant_id != work.tenant_id
                    || upload.state != UploadState::Quarantined
                    || upload.object_key != work.object_key
                {
                    return Err(UploadError::State);
                }
                match work.kind {
                    WorkKind::Verify => Ok(PreparedEffect::Verify(upload)),
                    WorkKind::Scan => {
                        let detected = upload.detected_mime.ok_or(UploadError::State)?;
                        if detected != upload.declared_mime {
                            return Err(UploadError::State);
                        }
                        Ok(PreparedEffect::Scan(
                            upload,
                            detected,
                            publication_started_at.ok_or(UploadError::State)?,
                        ))
                    }
                    WorkKind::Delete => unreachable!("delete preparation returned above"),
                }
            }
        }
    }

    async fn run_effect(
        &self,
        work: &crate::LeasedWork,
        prepared: &PreparedEffect<'_>,
        cancellation: &CancellationToken,
    ) -> EffectOutcome {
        match prepared {
            PreparedEffect::Verify(upload) => self.verify_effect(upload, cancellation).await,
            PreparedEffect::Scan(upload, detected, publication_started_at) => {
                self.scan_effect(upload, *detected, *publication_started_at, cancellation)
                    .await
            }
            PreparedEffect::Delete => self.delete_effect(work, cancellation).await,
        }
    }

    async fn verify_effect(
        &self,
        upload: &Upload,
        cancellation: &CancellationToken,
    ) -> EffectOutcome {
        let context = OperationContext::new(cancellation.clone());
        let object = match self
            .blob_store
            .get_stream(
                &context,
                GetRequest {
                    tenant_id: upload.tenant_id,
                    key: upload.object_key.clone(),
                    range: None,
                    condition: GetCondition::default(),
                    expected_sha256: Some(upload.expected_sha256.as_bytes()),
                },
            )
            .await
        {
            Ok(object) => object,
            Err(error) => return blob_failure_outcome(error),
        };
        if object.metadata.size != upload.declared_size {
            return EffectOutcome::Reject(RejectionReason::SizeMismatch);
        }
        let mut inspector = MimeInspector::default();
        let mut stream = object.stream;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => inspector.observe(&chunk),
                Err(error) => return blob_failure_outcome(error),
            }
        }
        match inspector.detected() {
            Ok(detected) if detected == upload.declared_mime => {
                EffectOutcome::CompleteVerification(detected)
            }
            Ok(_) | Err(_) => EffectOutcome::Reject(RejectionReason::MimeMismatch),
        }
    }

    async fn scan_effect(
        &self,
        upload: &Upload,
        detected: DeclaredMime,
        publication_started_at: OffsetDateTime,
        cancellation: &CancellationToken,
    ) -> EffectOutcome {
        let mut scanner = match self
            .scanner
            .start(
                ScanMetadata {
                    upload_id: upload.id,
                    declared_size: upload.declared_size,
                    expected_sha256: upload.expected_sha256,
                    detected_mime: detected,
                },
                cancellation,
            )
            .await
        {
            Ok(scanner) => scanner,
            Err(ScannerFailure::Retryable) => {
                return EffectOutcome::Retry(WorkFailureCode::ScannerUnavailable);
            }
            Err(ScannerFailure::Permanent) => {
                return EffectOutcome::Reject(RejectionReason::ScannerFailure);
            }
        };
        let context = OperationContext::new(cancellation.clone());
        let object = match self
            .blob_store
            .get_stream(
                &context,
                GetRequest {
                    tenant_id: upload.tenant_id,
                    key: upload.object_key.clone(),
                    range: None,
                    condition: GetCondition::default(),
                    expected_sha256: Some(upload.expected_sha256.as_bytes()),
                },
            )
            .await
        {
            Ok(object) => object,
            Err(error) => return blob_failure_outcome(error),
        };
        if object.metadata.size != upload.declared_size {
            return EffectOutcome::Reject(RejectionReason::SizeMismatch);
        }
        let mut inspector = MimeInspector::default();
        let mut stream = object.stream;
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => return blob_failure_outcome(error),
            };
            inspector.observe(&chunk);
            match scanner.scan_chunk(chunk, cancellation).await {
                Ok(()) => {}
                Err(ScannerFailure::Retryable) => {
                    return EffectOutcome::Retry(WorkFailureCode::ScannerUnavailable);
                }
                Err(ScannerFailure::Permanent) => {
                    return EffectOutcome::Reject(RejectionReason::ScannerFailure);
                }
            }
        }
        if inspector.detected().ok() != Some(upload.declared_mime) {
            return EffectOutcome::Reject(RejectionReason::MimeMismatch);
        }
        match scanner.finish(cancellation).await {
            Ok(ScanVerdict::Clean) => {
                self.publish_effect(upload, publication_started_at, cancellation)
                    .await
            }
            Ok(ScanVerdict::Malicious) => EffectOutcome::Reject(RejectionReason::Malware),
            Err(ScannerFailure::Retryable) => {
                EffectOutcome::Retry(WorkFailureCode::ScannerUnavailable)
            }
            Err(ScannerFailure::Permanent) => {
                EffectOutcome::Reject(RejectionReason::ScannerFailure)
            }
        }
    }

    async fn publish_effect(
        &self,
        upload: &Upload,
        publication_started_at: OffsetDateTime,
        cancellation: &CancellationToken,
    ) -> EffectOutcome {
        let context = OperationContext::new(cancellation.clone());
        match self
            .blob_store
            .copy(
                &context,
                TransferRequest {
                    tenant_id: upload.tenant_id,
                    source: upload.object_key.clone(),
                    destination: upload.published_object_key.clone(),
                    create_only: false,
                },
            )
            .await
        {
            Ok(()) => EffectOutcome::CompleteScanClean(publication_started_at),
            Err(error) => blob_failure_outcome(error),
        }
    }

    async fn delete_effect(
        &self,
        work: &crate::LeasedWork,
        cancellation: &CancellationToken,
    ) -> EffectOutcome {
        let context = OperationContext::new(cancellation.clone());
        match self
            .blob_store
            .delete(&context, work.tenant_id, &work.object_key)
            .await
        {
            Ok(()) => EffectOutcome::CompleteDelete,
            Err(BlobStoreError::Timeout) => EffectOutcome::Retry(WorkFailureCode::Timeout),
            Err(BlobStoreError::Cancelled | BlobStoreError::Shutdown) => {
                EffectOutcome::Retry(WorkFailureCode::Cancelled)
            }
            Err(_) => EffectOutcome::Retry(WorkFailureCode::StorageUnavailable),
        }
    }

    async fn finalize_with_margin(
        &self,
        work: &crate::LeasedWork,
        outcome: EffectOutcome,
    ) -> Result<(), UploadError> {
        match tokio::time::timeout(
            self.config.finalization_margin,
            self.finalize_effect(work, outcome),
        )
        .await
        {
            Ok(Ok(()) | Err(UploadError::LostLease)) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(UploadError::Timeout),
        }
    }

    async fn finalize_cancelled(&self, work: &crate::LeasedWork) -> Result<(), UploadError> {
        self.finalize_with_margin(work, EffectOutcome::Retry(WorkFailureCode::Cancelled))
            .await
    }

    async fn finalize_effect(
        &self,
        work: &crate::LeasedWork,
        outcome: EffectOutcome,
    ) -> Result<(), UploadError> {
        match outcome {
            EffectOutcome::CompleteVerification(detected) => {
                self.repository
                    .complete_verification(work, detected)
                    .await?;
                counter!("omnius_upload_reconciliation_total", "kind" => "verify", "result" => "complete")
                    .increment(1);
            }
            EffectOutcome::CompleteScanClean(publication_started_at) => {
                self.repository
                    .complete_scan_clean(work, publication_started_at)
                    .await?;
                counter!("omnius_upload_reconciliation_total", "kind" => "scan", "result" => "clean")
                    .increment(1);
            }
            EffectOutcome::CompleteDelete => {
                self.repository.complete_delete(work).await?;
                counter!("omnius_upload_reconciliation_total", "kind" => "delete", "result" => "complete")
                    .increment(1);
            }
            EffectOutcome::Reject(reason) => {
                self.repository.reject_leased(work, reason).await?;
                counter!("omnius_upload_reconciliation_total", "kind" => work.kind.as_str(), "result" => "rejected")
                    .increment(1);
            }
            EffectOutcome::Retry(code) => {
                self.repository
                    .retry(work, code, self.config.retry_delay(work.attempt_count))
                    .await?;
            }
        }
        Ok(())
    }
}

enum PreparedEffect<'a> {
    Verify(&'a Upload),
    Scan(&'a Upload, DeclaredMime, OffsetDateTime),
    Delete,
}

#[derive(Clone, Copy, Debug)]
enum EffectOutcome {
    CompleteVerification(DeclaredMime),
    CompleteScanClean(OffsetDateTime),
    CompleteDelete,
    Reject(RejectionReason),
    Retry(WorkFailureCode),
}

fn blob_failure_outcome(error: BlobStoreError) -> EffectOutcome {
    match error {
        BlobStoreError::NotFound => EffectOutcome::Reject(RejectionReason::MissingObject),
        BlobStoreError::Checksum => EffectOutcome::Reject(RejectionReason::ChecksumMismatch),
        BlobStoreError::Size => EffectOutcome::Reject(RejectionReason::SizeMismatch),
        BlobStoreError::Timeout => EffectOutcome::Retry(WorkFailureCode::Timeout),
        BlobStoreError::Cancelled | BlobStoreError::Shutdown => {
            EffectOutcome::Retry(WorkFailureCode::Cancelled)
        }
        _ => EffectOutcome::Retry(WorkFailureCode::StorageUnavailable),
    }
}

fn task_error() -> ServiceError {
    ServiceError::new(task_error_code(), "upload reconciliation unavailable")
}

fn task_error_code() -> ErrorCode {
    match ErrorCode::try_new("UPLOAD_RECONCILIATION_UNAVAILABLE") {
        Ok(code) => code,
        Err(_) => unreachable!("static upload reconciliation error code must be valid"),
    }
}
