use std::{fmt, sync::Arc, time::Duration};

use metrics::counter;
use omnius_core::{ErrorCode, ServiceError};
use omnius_jobs_core::{EnqueueError, JobEnqueuer};
use omnius_runtime::{Criticality, RestartPolicy, TaskContext, TaskSpec};
use thiserror::Error;

use crate::{
    DeliveryRecord, DeliveryStatus, NotificationError, NotificationRequest,
    PostgresNotificationRepository, repository::PendingOutbox,
};

const OUTBOX_LEASE: Duration = Duration::from_secs(30);
const RECOVERY_TASK_NAME: &str = "notification-recovery";
const MODULE_NAME: &str = "notifications";
const RECOVERY_ERROR_CODE: &str = "NOTIFICATION_RECOVERY_UNAVAILABLE";
const MAX_RECOVERY_INTERVAL: Duration = Duration::from_mins(5);
const MAX_RECOVERY_SHUTDOWN: Duration = Duration::from_mins(5);
const MAX_RECOVERY_BATCH: u16 = 100;

/// Bounded notification recovery-task policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotificationRecoveryConfig {
    batch_size: u16,
    poll_interval: Duration,
    shutdown_timeout: Duration,
    restart: RestartPolicy,
}

impl NotificationRecoveryConfig {
    /// Creates a bounded recovery policy.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationRecoveryConfigError`] for a zero or excessive bound.
    pub fn new(
        batch_size: u16,
        poll_interval: Duration,
        shutdown_timeout: Duration,
        restart: RestartPolicy,
    ) -> Result<Self, NotificationRecoveryConfigError> {
        if batch_size == 0 || batch_size > MAX_RECOVERY_BATCH {
            return Err(NotificationRecoveryConfigError::InvalidBatchSize);
        }
        if poll_interval.is_zero() || poll_interval > MAX_RECOVERY_INTERVAL {
            return Err(NotificationRecoveryConfigError::InvalidPollInterval);
        }
        if shutdown_timeout.is_zero() || shutdown_timeout > MAX_RECOVERY_SHUTDOWN {
            return Err(NotificationRecoveryConfigError::InvalidShutdownTimeout);
        }
        Ok(Self {
            batch_size,
            poll_interval,
            shutdown_timeout,
            restart,
        })
    }
}

/// Invalid bounded notification recovery policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NotificationRecoveryConfigError {
    /// Dispatch batch was outside 1 through 100.
    #[error("notification recovery batch size is invalid")]
    InvalidBatchSize,
    /// Polling cadence was zero or too large.
    #[error("notification recovery poll interval is invalid")]
    InvalidPollInterval,
    /// Task shutdown bound was zero or too large.
    #[error("notification recovery shutdown timeout is invalid")]
    InvalidShutdownTimeout,
}

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

    /// Builds the degraded supervised recovery task.
    #[must_use]
    pub fn recovery_task(&self, config: NotificationRecoveryConfig) -> TaskSpec {
        let orchestrator = self.clone();
        TaskSpec::new(
            RECOVERY_TASK_NAME,
            MODULE_NAME,
            Criticality::Degraded,
            config.shutdown_timeout,
            move |context| {
                let orchestrator = orchestrator.clone();
                async move { run_recovery(orchestrator, config, context).await }
            },
        )
        .with_restart_policy(config.restart)
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

async fn run_recovery(
    orchestrator: NotificationOrchestrator,
    config: NotificationRecoveryConfig,
    context: TaskContext,
) -> Result<(), ServiceError> {
    loop {
        if context.is_draining() || context.is_shutdown_requested() || context.is_cancelled() {
            return Ok(());
        }
        orchestrator
            .run_once(config.batch_size)
            .await
            .map_err(|_| recovery_error())?;
        context.heartbeat();
        tokio::select! {
            () = context.draining() => return Ok(()),
            () = context.shutdown_requested() => return Ok(()),
            () = context.cancelled() => return Ok(()),
            () = tokio::time::sleep(config.poll_interval) => {}
        }
    }
}

fn recovery_error() -> ServiceError {
    ServiceError::new(recovery_error_code(), "notification recovery unavailable")
}

fn recovery_error_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(RECOVERY_ERROR_CODE) else {
        unreachable!("static notification recovery error code must be valid")
    };
    code
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
