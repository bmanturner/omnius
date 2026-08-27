use std::{fmt, sync::Arc};

use futures::{StreamExt as _, future::BoxFuture, stream};
use metrics::counter;
use omnius_core::{ErrorCode, ServiceError};
use omnius_runtime::{Criticality, RestartPolicy, TaskContext, TaskSpec};
use omnius_tenancy::TenantContext;
use omnius_webhooks_inbound::{ClaimedReceipt, FailureClass, HandlerError, WebhookHandler};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    BillingProviderAdapter, BillingStoreError, ClaimedReconciliation, ClaimedUsage,
    EffectiveEntitlement, EventEnqueueOutcome, NewUsageRecord, PostgresBillingStore,
    ProviderAdapterError, ReconciliationTaskId, RepairEnqueueOutcome, RepairIdempotencyKey,
    SnapshotApplyOutcome, UsageCompletionOutcome, UsageRecordOutcome, UsageRecordState,
};

/// Stable required supervisor task name for durable billing recovery.
pub const BILLING_RECOVERY_TASK_NAME: &str = "billing-recovery";
const BILLING_MODULE_NAME: &str = "billing";
const BILLING_RECOVERY_ERROR_CODE: &str = "billing_recovery_unavailable";

/// Application service joining an exact provider adapter to durable PostgreSQL billing state.
///
/// Provider calls never run inside a database transaction. A snapshot is fetched first and only
/// then published under the task's live database lease and monotonic provider revision fence.
#[derive(Clone)]
pub struct BillingReconciler<A> {
    provider: Arc<A>,
    store: PostgresBillingStore,
}

impl<A: BillingProviderAdapter> BillingReconciler<A> {
    /// Creates a reconciler for one exact provider adapter.
    #[must_use]
    pub const fn new(provider: Arc<A>, store: PostgresBillingStore) -> Self {
        Self { provider, store }
    }

    /// Returns the provider adapter.
    #[must_use]
    pub const fn provider(&self) -> &Arc<A> {
        &self.provider
    }

    /// Returns the durable local store.
    #[must_use]
    pub const fn store(&self) -> &PostgresBillingStore {
        &self.store
    }

    /// Enqueues and attempts reconciliation for one verified inbound receipt.
    ///
    /// The durable billing event fence is independent of the inbound receipt fence. Exact replays
    /// are idempotent; out-of-order events and identity conflicts return permanent fail-closed
    /// errors without mutating mirrors.
    ///
    /// # Errors
    ///
    /// Returns [`BillingServiceError`] for exact-provider decoding, fencing, leasing, provider API,
    /// persistence, cancellation, or snapshot publication failures.
    pub async fn handle_verified_receipt(
        &self,
        receipt: &ClaimedReceipt,
        cancellation: &CancellationToken,
    ) -> Result<(), BillingServiceError> {
        if cancellation.is_cancelled() {
            return Err(BillingServiceError::Cancelled);
        }
        let event = self
            .provider
            .decode_verified_event(receipt)
            .map_err(|error| classify_provider(&error))?;
        let fingerprint = receipt_fingerprint(receipt)?;
        let task_id = match self
            .store
            .enqueue_verified_event(
                self.provider.provider_id(),
                &event,
                receipt.id(),
                fingerprint,
            )
            .await
            .map_err(classify_store)?
        {
            EventEnqueueOutcome::Enqueued(id) | EventEnqueueOutcome::Duplicate(id) => id,
            EventEnqueueOutcome::OutOfOrder => {
                return Err(BillingServiceError::OutOfOrderEvent);
            }
            EventEnqueueOutcome::Conflict => return Err(BillingServiceError::EventConflict),
        };
        self.process_task_if_ready(task_id, cancellation).await
    }

    /// Claims and processes a named durable reconciliation task when it is eligible.
    ///
    /// A missing claim succeeds only after terminal database state. Live, delayed, or concurrently
    /// leased work remains retryable so its wake-up trigger is never silently acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`BillingServiceError`] for provider, lease, or publication failures.
    pub async fn process_task_if_ready(
        &self,
        task_id: ReconciliationTaskId,
        cancellation: &CancellationToken,
    ) -> Result<(), BillingServiceError> {
        let Some(claim) = self
            .store
            .claim_task(task_id)
            .await
            .map_err(classify_store)?
        else {
            return if self
                .store
                .task_is_terminal(task_id)
                .await
                .map_err(classify_store)?
            {
                Ok(())
            } else {
                Err(BillingServiceError::RetryableLocal)
            };
        };
        self.process_claim(&claim, cancellation).await
    }

    /// Processes one bounded database claim.
    ///
    /// # Errors
    ///
    /// Returns [`BillingServiceError`] after durably retrying or dead-lettering classified provider
    /// failures when the lease remains live.
    pub async fn process_claim(
        &self,
        claim: &ClaimedReconciliation,
        cancellation: &CancellationToken,
    ) -> Result<(), BillingServiceError> {
        if claim.provider() != self.provider.provider_id() {
            self.store
                .dead_letter_task(claim, "provider_mismatch")
                .await
                .map_err(classify_store)?;
            return Err(BillingServiceError::ProviderMismatch);
        }
        if cancellation.is_cancelled() {
            self.store
                .retry_task(claim, "cancelled")
                .await
                .map_err(classify_store)?;
            return Err(BillingServiceError::Cancelled);
        }
        let fetched = tokio::select! {
            () = cancellation.cancelled() => {
                self.store
                    .retry_task(claim, "cancelled")
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::Cancelled);
            }
            result = tokio::time::timeout(
                self.store.config().provider_timeout,
                self.provider.fetch_snapshot(claim.tenant_id()),
            ) => result,
        };
        let snapshot = match fetched {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(error)) if error.is_retryable() => {
                self.store
                    .retry_task(claim, error.class().as_str())
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::RetryableProvider);
            }
            Ok(Err(error)) => {
                self.store
                    .dead_letter_task(claim, error.class().as_str())
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::PermanentProvider);
            }
            Err(_) => {
                self.store
                    .retry_task(claim, "provider_timeout")
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::RetryableProvider);
            }
        };
        if cancellation.is_cancelled() {
            self.store
                .retry_task(claim, "cancelled")
                .await
                .map_err(classify_store)?;
            return Err(BillingServiceError::Cancelled);
        }
        let outcome = match self.store.apply_snapshot(claim, &snapshot).await {
            Ok(outcome) => outcome,
            Err(
                error @ (BillingStoreError::Database(_)
                | BillingStoreError::Connection(_)
                | BillingStoreError::Audit
                | BillingStoreError::Outbox),
            ) => {
                self.store
                    .retry_task(claim, "local_retryable")
                    .await
                    .map_err(classify_store)?;
                return Err(classify_store(error));
            }
            Err(BillingStoreError::LostLease) => {
                return Err(BillingServiceError::RetryableLocal);
            }
            Err(error) => {
                self.store
                    .dead_letter_task(claim, "snapshot_invalid")
                    .await
                    .map_err(classify_store)?;
                return Err(classify_store(error));
            }
        };
        match outcome {
            SnapshotApplyOutcome::Applied { .. }
            | SnapshotApplyOutcome::Duplicate
            | SnapshotApplyOutcome::Stale => {
                counter!("omnius_billing_reconciler_total", "result" => "succeeded").increment(1);
                Ok(())
            }
            SnapshotApplyOutcome::Conflict => Err(BillingServiceError::SnapshotConflict),
        }
    }

    /// Claims and processes one bounded ready batch for a durable worker loop.
    ///
    /// # Errors
    ///
    /// Returns the first safe processing failure after every claim in the batch has finished.
    pub async fn process_ready(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<usize, BillingServiceError> {
        let claims = self
            .store
            .claim_ready(self.provider.provider_id())
            .await
            .map_err(classify_store)?;
        let count = claims.len();
        if count == 0 {
            return Ok(0);
        }
        let results = stream::iter(claims)
            .map(|claim| async move { self.process_claim(&claim, cancellation).await })
            .buffer_unordered(count)
            .collect::<Vec<_>>()
            .await;
        for result in results {
            match result {
                Err(error) if !durably_terminal(error) => return Err(error),
                Ok(()) | Err(_) => {}
            }
        }
        Ok(count)
    }

    /// Enqueues an operator repair through the authoritative tenant context.
    ///
    /// # Errors
    ///
    /// Returns a safe provider or persistence error.
    pub async fn request_repair(
        &self,
        context: &TenantContext,
        idempotency_key: &RepairIdempotencyKey,
    ) -> Result<RepairEnqueueOutcome, BillingServiceError> {
        self.store
            .request_repair(context, self.provider.provider_id(), idempotency_key)
            .await
            .map_err(classify_store)
    }

    /// Reads only reconciled local entitlements within an authoritative tenant context.
    ///
    /// # Errors
    ///
    /// Returns a safe local persistence error. This path never calls the provider.
    pub async fn entitlements(
        &self,
        context: &TenantContext,
    ) -> Result<Vec<EffectiveEntitlement>, BillingServiceError> {
        self.store
            .entitlements(context)
            .await
            .map_err(classify_store)
    }

    /// Records usage under a local concurrency fence, submits it with provider idempotency, and
    /// persists the verified acknowledgement under a durable usage lease.
    ///
    /// # Errors
    ///
    /// Returns a permanent conflict for key reuse, a classified provider error, or a safe local
    /// persistence error. Retryable failures are durably delayed for [`Self::process_pending_usage`].
    pub async fn submit_usage(
        &self,
        context: &TenantContext,
        usage: &NewUsageRecord,
    ) -> Result<UsageCompletionOutcome, BillingServiceError> {
        let tenant_id = context.membership().organization_id;
        let record_id = match self
            .store
            .record_usage(context, self.provider.provider_id(), usage)
            .await
            .map_err(classify_store)?
        {
            UsageRecordOutcome::Recorded(id) | UsageRecordOutcome::Duplicate(id) => id,
            UsageRecordOutcome::Conflict => return Err(BillingServiceError::UsageConflict),
        };
        let claim = self
            .store
            .claim_usage(record_id)
            .await
            .map_err(classify_store)?;
        let Some(claim) = claim else {
            return match self
                .store
                .usage_state(tenant_id, record_id)
                .await
                .map_err(classify_store)?
            {
                UsageRecordState::Accepted => Ok(UsageCompletionOutcome::Duplicate),
                UsageRecordState::Rejected => Err(BillingServiceError::UsageRejected),
                UsageRecordState::Pending => Err(BillingServiceError::RetryableLocal),
            };
        };
        self.process_usage_claim(&claim).await
    }

    /// Submits one leased usage fact and durably records retry, rejection, or acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a classified provider, provider-mismatch, or local persistence failure.
    pub async fn process_usage_claim(
        &self,
        claim: &ClaimedUsage,
    ) -> Result<UsageCompletionOutcome, BillingServiceError> {
        if claim.provider() != self.provider.provider_id() {
            self.store
                .reject_usage(claim, "provider_mismatch")
                .await
                .map_err(classify_store)?;
            return Err(BillingServiceError::ProviderMismatch);
        }
        let submitted = tokio::time::timeout(
            self.store.config().provider_timeout,
            self.provider.submit_usage(claim.request()),
        )
        .await;
        let acknowledgement = match submitted {
            Ok(Ok(acknowledgement)) => acknowledgement,
            Ok(Err(error)) if error.is_retryable() => {
                self.store
                    .retry_usage(claim, error.class().as_str())
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::RetryableProvider);
            }
            Ok(Err(error)) => {
                self.store
                    .reject_usage(claim, error.class().as_str())
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::PermanentProvider);
            }
            Err(_) => {
                self.store
                    .retry_usage(claim, "provider_timeout")
                    .await
                    .map_err(classify_store)?;
                return Err(BillingServiceError::RetryableProvider);
            }
        };
        match self.store.complete_usage(claim, &acknowledgement).await {
            Ok(outcome) => Ok(outcome),
            Err(BillingStoreError::Conflict) => {
                self.store
                    .reject_usage(claim, "provider_usage_conflict")
                    .await
                    .map_err(classify_store)?;
                Err(BillingServiceError::UsageConflict)
            }
            Err(error) => Err(classify_store(error)),
        }
    }

    /// Claims and concurrently redrives one bounded batch of durable pending usage.
    ///
    /// # Errors
    ///
    /// Returns the first safe failure after every leased item in the batch has finished.
    pub async fn process_pending_usage(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<usize, BillingServiceError> {
        let claims = self
            .store
            .claim_ready_usage(self.provider.provider_id())
            .await
            .map_err(classify_store)?;
        let count = claims.len();
        if count == 0 {
            return Ok(0);
        }
        let results = stream::iter(claims)
            .map(|claim| async move {
                if cancellation.is_cancelled() {
                    self.store
                        .retry_usage(&claim, "cancelled")
                        .await
                        .map_err(classify_store)?;
                    return Err(BillingServiceError::Cancelled);
                }
                self.process_usage_claim(&claim).await.map(|_| ())
            })
            .buffer_unordered(count)
            .collect::<Vec<_>>()
            .await;
        for result in results {
            match result {
                Err(error) if !durably_terminal(error) => return Err(error),
                Ok(()) | Err(_) => {}
            }
        }
        Ok(count)
    }

    /// Builds the mandatory periodic scanner for orphan-proof reconciliation and usage redrive.
    #[must_use]
    pub fn recovery_task(&self) -> TaskSpec {
        let provider = Arc::clone(&self.provider);
        let store = self.store.clone();
        let config = self.store.config();
        TaskSpec::new(
            BILLING_RECOVERY_TASK_NAME,
            BILLING_MODULE_NAME,
            Criticality::Required,
            config.scanner_shutdown_timeout,
            move |context| {
                let reconciler = BillingReconciler {
                    provider: Arc::clone(&provider),
                    store: store.clone(),
                };
                async move { run_recovery_scanner(reconciler, context).await }
            },
        )
        .with_restart_policy(RestartPolicy::on_failure(
            10,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(30),
            20,
        ))
    }
}

async fn run_recovery_scanner<A: BillingProviderAdapter>(
    reconciler: BillingReconciler<A>,
    context: TaskContext,
) -> Result<(), ServiceError> {
    loop {
        context.heartbeat();
        if context.is_draining() || context.is_shutdown_requested() || context.is_cancelled() {
            return Ok(());
        }
        let cancellation = CancellationToken::new();
        let cycle = async {
            reconciler.process_ready(&cancellation).await?;
            reconciler.process_pending_usage(&cancellation).await?;
            Ok::<(), BillingServiceError>(())
        };
        tokio::pin!(cycle);
        tokio::select! {
            result = &mut cycle => result.map_err(|_| recovery_error())?,
            () = context.draining() => {
                cancellation.cancel();
                return Ok(());
            }
            () = context.shutdown_requested() => {
                cancellation.cancel();
                return Ok(());
            }
            () = context.cancelled() => {
                cancellation.cancel();
                return Ok(());
            }
        }
        tokio::select! {
            () = tokio::time::sleep(reconciler.store.config().scanner_interval) => {}
            () = context.draining() => return Ok(()),
            () = context.shutdown_requested() => return Ok(()),
            () = context.cancelled() => return Ok(()),
        }
    }
}

fn recovery_error() -> ServiceError {
    let code = ErrorCode::try_new(BILLING_RECOVERY_ERROR_CODE)
        .unwrap_or_else(|_| unreachable!("static billing recovery error code must be valid"));
    ServiceError::new(code, "billing recovery scanner unavailable")
}
fn durably_terminal(error: BillingServiceError) -> bool {
    matches!(
        error,
        BillingServiceError::PermanentProvider
            | BillingServiceError::OutOfOrderEvent
            | BillingServiceError::EventConflict
            | BillingServiceError::SnapshotConflict
            | BillingServiceError::UsageConflict
            | BillingServiceError::UsageRejected
            | BillingServiceError::ProviderMismatch
            | BillingServiceError::PermanentLocal
    )
}

impl<A> fmt::Debug for BillingReconciler<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BillingReconciler")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl<A: BillingProviderAdapter> WebhookHandler for BillingReconciler<A> {
    fn handle<'a>(
        &'a self,
        receipt: &'a ClaimedReceipt,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            self.handle_verified_receipt(receipt, cancellation)
                .await
                .map_err(webhook_error)
        })
    }
}

/// Safe application-level billing reconciliation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BillingServiceError {
    /// A transient provider operation was durably scheduled for retry.
    #[error("billing provider operation is retryable")]
    RetryableProvider,
    /// A permanent provider operation was durably dead-lettered.
    #[error("billing provider operation is permanent")]
    PermanentProvider,
    /// The provider event was behind the monotonic event fence.
    #[error("billing provider event is out of order")]
    OutOfOrderEvent,
    /// A provider event identity or sequence conflicted with durable facts.
    #[error("billing provider event conflicts with durable state")]
    EventConflict,
    /// A provider snapshot revision was reused with different content.
    #[error("billing provider snapshot conflicts with durable state")]
    SnapshotConflict,
    /// Usage idempotency identity was reused with different facts or acknowledgement.
    #[error("billing usage identity conflicts with durable state")]
    UsageConflict,
    /// The exact usage record reached a durable rejected terminal state.
    #[error("billing usage was permanently rejected")]
    UsageRejected,
    /// The claimed task belongs to another exact provider adapter.
    #[error("billing provider does not match durable task")]
    ProviderMismatch,
    /// Cooperative cancellation interrupted work before publication.
    #[error("billing operation was cancelled")]
    Cancelled,
    /// A retryable local database, audit, outbox, or lease operation failed.
    #[error("billing local operation failed transiently")]
    RetryableLocal,
    /// Local validated input or immutable state was permanently invalid.
    #[error("billing local operation failed permanently")]
    PermanentLocal,
}

fn receipt_fingerprint(receipt: &ClaimedReceipt) -> Result<[u8; 32], BillingServiceError> {
    let payload = serde_json::to_vec(receipt.parsed_payload())
        .map_err(|_| BillingServiceError::PermanentLocal)?;
    let mut digest = Sha256::new();
    digest.update(receipt.provider().as_str().as_bytes());
    digest.update([0]);
    digest.update(receipt.scope().as_bytes());
    digest.update([0]);
    digest.update(receipt.event_id().as_bytes());
    digest.update([0]);
    digest.update(receipt.event_type().as_bytes());
    digest.update(receipt.event_version().to_be_bytes());
    digest.update(payload);
    Ok(digest.finalize().into())
}

fn classify_provider(error: &ProviderAdapterError) -> BillingServiceError {
    if error.is_retryable() {
        BillingServiceError::RetryableProvider
    } else {
        BillingServiceError::PermanentProvider
    }
}

fn classify_store(error: BillingStoreError) -> BillingServiceError {
    match error {
        BillingStoreError::Database(source) => {
            drop(source);
            BillingServiceError::RetryableLocal
        }
        BillingStoreError::Connection(source) => {
            let _ = source;
            BillingServiceError::RetryableLocal
        }
        BillingStoreError::Audit | BillingStoreError::Outbox | BillingStoreError::LostLease => {
            BillingServiceError::RetryableLocal
        }
        BillingStoreError::Constraint(source) => {
            drop(source);
            BillingServiceError::PermanentLocal
        }
        BillingStoreError::InvalidConfiguration
        | BillingStoreError::InvalidValue
        | BillingStoreError::InvalidSnapshot
        | BillingStoreError::ProviderMismatch
        | BillingStoreError::Conflict
        | BillingStoreError::NotFound
        | BillingStoreError::Encoding
        | BillingStoreError::CorruptState => BillingServiceError::PermanentLocal,
    }
}

fn webhook_error(error: BillingServiceError) -> HandlerError {
    let retryable = matches!(
        error,
        BillingServiceError::RetryableProvider
            | BillingServiceError::RetryableLocal
            | BillingServiceError::Cancelled
    );
    let class = if retryable {
        failure_class("billing_retryable")
    } else {
        failure_class("billing_permanent")
    };
    if retryable {
        HandlerError::Retryable(class)
    } else {
        HandlerError::Permanent(class)
    }
}

fn failure_class(value: &str) -> FailureClass {
    FailureClass::parse(value).unwrap_or_else(|_| FailureClass::unsupported_event())
}
