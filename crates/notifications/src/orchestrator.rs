use std::{fmt, sync::Arc, time::Duration};

use metrics::counter;
use omnius_jobs_core::{EnqueueError, JobEnqueuer};

use crate::{
    DeliveryRecord, DeliveryStatus, NotificationError, NotificationRequest,
    PostgresNotificationRepository, repository::PendingOutbox,
};

const OUTBOX_LEASE: Duration = Duration::from_secs(30);

/// Per-channel durable scheduling result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledDelivery {
    /// Current authoritative state.
    pub delivery: DeliveryRecord,
    /// Whether this call inserted the intent rather than finding its dedupe identity.
    pub inserted: bool,
}

/// Complete multi-channel schedule result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleOutcome {
    /// One result for every requested channel, in request order.
    pub deliveries: Vec<ScheduledDelivery>,
}

/// Bounded outbox dispatch summary with no tenant or request labels.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchReport {
    /// Successfully accepted exact envelopes.
    pub accepted: u16,
    /// Provider temporarily could not accept envelopes; PostgreSQL retained them.
    pub deferred: u16,
    /// Persisted envelope or receipt failed an invariant.
    pub rejected: u16,
}

/// Durable notification intent orchestration and PostgreSQL outbox dispatch.
#[derive(Clone)]
pub struct NotificationOrchestrator {
    repository: PostgresNotificationRepository,
    enqueuer: Arc<dyn JobEnqueuer>,
}

impl NotificationOrchestrator {
    /// Creates the orchestrator without taking ownership of queue or database lifecycle.
    #[must_use]
    pub fn new(repository: PostgresNotificationRepository, enqueuer: Arc<dyn JobEnqueuer>) -> Self {
        Self {
            repository,
            enqueuer,
        }
    }

    /// Persists every channel intent and its exact job envelope before attempting provider enqueue.
    ///
    /// Provider unavailability never loses an accepted intent: it remains `pending_dispatch` for
    /// [`Self::dispatch_pending`]. Duplicate calls return the existing tenant/channel/window row.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError`] when PostgreSQL cannot durably record or reload an intent,
    /// when an exact job envelope is invalid, or when outbox state is inconsistent.
    pub async fn schedule(
        &self,
        request: &NotificationRequest,
    ) -> Result<ScheduleOutcome, NotificationError> {
        let mut deliveries = Vec::with_capacity(request.channels().len());
        for &channel in request.channels() {
            let persisted = self.repository.schedule_channel(request, channel).await?;
            if persisted.has_pending_outbox {
                let _ = self
                    .dispatch_one(persisted.record.tenant_id, persisted.record.id)
                    .await?;
            }
            let current = self
                .repository
                .get_delivery(persisted.record.tenant_id, persisted.record.id)
                .await?;
            deliveries.push(ScheduledDelivery {
                delivery: current,
                inserted: persisted.inserted,
            });
        }
        Ok(ScheduleOutcome { deliveries })
    }

    /// Recovers stale delivery claims, releases bounded due digest buckets, then dispatches
    /// available outbox rows.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::InvalidRequest`] when `limit` is zero or exceeds 100, or a
    /// persistence/envelope error while releasing or dispatching work.
    pub async fn run_once(&self, limit: u16) -> Result<DispatchReport, NotificationError> {
        self.repository.recover_stale_deliveries(limit).await?;
        self.repository.release_due_digests(limit).await?;
        self.dispatch_pending(limit).await
    }

    /// Claims and dispatches a bounded number of exact persisted envelopes.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::InvalidRequest`] when `limit` is zero or exceeds 100, or a
    /// persistence/envelope error while claiming or dispatching work.
    pub async fn dispatch_pending(&self, limit: u16) -> Result<DispatchReport, NotificationError> {
        let pending = self
            .repository
            .claim_pending_outbox(limit, OUTBOX_LEASE)
            .await?;
        let mut report = DispatchReport::default();
        for item in pending {
            match self.dispatch_claimed(&item).await? {
                DispatchResult::Accepted => report.accepted = report.accepted.saturating_add(1),
                DispatchResult::Deferred => report.deferred = report.deferred.saturating_add(1),
                DispatchResult::Rejected => report.rejected = report.rejected.saturating_add(1),
            }
        }
        Ok(report)
    }

    async fn dispatch_one(
        &self,
        tenant_id: omnius_auth_core::TenantId,
        delivery_id: crate::DeliveryId,
    ) -> Result<Option<DispatchResult>, NotificationError> {
        let Some(pending) = self
            .repository
            .claim_delivery_outbox(tenant_id, delivery_id, OUTBOX_LEASE)
            .await?
        else {
            return Ok(None);
        };
        self.dispatch_claimed(&pending).await.map(Some)
    }

    async fn dispatch_claimed(
        &self,
        pending: &PendingOutbox,
    ) -> Result<DispatchResult, NotificationError> {
        match self.enqueuer.enqueue(pending.envelope.clone()).await {
            Ok(receipt) if receipt.job_id() == pending.job_id => {
                self.repository
                    .mark_dispatched(pending, receipt.job_id(), receipt.accepted_at())
                    .await?;
                counter!("omnius_notifications_outbox_total", "result" => "accepted").increment(1);
                Ok(DispatchResult::Accepted)
            }
            Ok(_) => {
                self.repository
                    .release_outbox(pending, "notification_receipt_mismatch")
                    .await?;
                counter!("omnius_notifications_outbox_total", "result" => "rejected").increment(1);
                Ok(DispatchResult::Rejected)
            }
            Err(error) => {
                let (code, result) = enqueue_failure(error);
                self.repository.release_outbox(pending, code).await?;
                counter!("omnius_notifications_outbox_total", "result" => match result { DispatchResult::Deferred => "deferred", DispatchResult::Rejected => "rejected", DispatchResult::Accepted => "accepted" }).increment(1);
                Ok(result)
            }
        }
    }
}

impl fmt::Debug for NotificationOrchestrator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationOrchestrator")
            .field("repository", &self.repository)
            .field("enqueuer", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchResult {
    Accepted,
    Deferred,
    Rejected,
}

const fn enqueue_failure(error: EnqueueError) -> (&'static str, DispatchResult) {
    match error {
        EnqueueError::Capacity => ("notification_queue_capacity", DispatchResult::Deferred),
        EnqueueError::Unavailable => ("notification_queue_unavailable", DispatchResult::Deferred),
        EnqueueError::InvalidEnvelope => {
            ("notification_envelope_invalid", DispatchResult::Rejected)
        }
        EnqueueError::Rejected => ("notification_queue_rejected", DispatchResult::Rejected),
    }
}

/// Returns whether a schedule result still relies on outbox recovery.
#[must_use]
pub fn is_pending_dispatch(result: &ScheduledDelivery) -> bool {
    result.delivery.status == DeliveryStatus::PendingDispatch
}
