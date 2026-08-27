use futures::future::BoxFuture;
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, FailureCode, HandlerFailure,
    HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobPolicy, TypedJobHandler,
};
use serde::{Deserialize, Serialize};

use crate::{BillingProviderAdapter, BillingReconciler, BillingServiceError, ReconciliationTaskId};

const RECONCILE_BILLING_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Optional,
    10,
    1_000,
    60_000,
    2,
    Jitter::Full,
    300,
    16,
    Some(600),
    "billing",
    5,
    604_800,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    256,
) {
    Ok(policy) => policy,
    Err(_) => panic!("static billing reconciliation job policy must be valid"),
};

/// At-least-once trigger for one durable PostgreSQL billing reconciliation task.
///
/// The task ID is only a wake-up hint. Provider effects and mirror publication are fenced by the
/// task's database lease and provider revision, not by queue delivery identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconcileBillingJob {
    task_id: ReconciliationTaskId,
}

impl ReconcileBillingJob {
    /// Creates a wake-up trigger for a durable task.
    #[must_use]
    pub const fn new(task_id: ReconciliationTaskId) -> Self {
        Self { task_id }
    }

    /// Returns the durable reconciliation task identity.
    #[must_use]
    pub const fn task_id(self) -> ReconciliationTaskId {
        self.task_id
    }
}

impl Job for ReconcileBillingJob {
    const NAME: &'static str = "billing.reconcile";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = RECONCILE_BILLING_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_job_billing_reconcile";
    const RUNBOOK: &'static str = "runbooks/billing-reconcile";
}

/// `jobs-core` handler that claims and processes the durable task named by a trigger.
pub struct ReconcileBillingJobHandler<A> {
    reconciler: BillingReconciler<A>,
}

impl<A> ReconcileBillingJobHandler<A> {
    /// Creates a typed handler over the application reconciler.
    #[must_use]
    pub const fn new(reconciler: BillingReconciler<A>) -> Self {
        Self { reconciler }
    }
}

impl<A: BillingProviderAdapter> TypedJobHandler<ReconcileBillingJob>
    for ReconcileBillingJobHandler<A>
{
    fn handle(
        &self,
        job: ReconcileBillingJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            if context.is_cancelled() {
                return HandlerOutcome::Cancelled;
            }
            service_outcome(
                self.reconciler
                    .process_task_if_ready(job.task_id(), context.cancellation())
                    .await,
            )
        })
    }
}

/// Periodic jobs-core trigger that redrives a bounded batch of durable pending usage.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedriveBillingUsageJob;

impl Job for RedriveBillingUsageJob {
    const NAME: &'static str = "billing.usage_redrive";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = RECONCILE_BILLING_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_job_billing_usage_redrive";
    const RUNBOOK: &'static str = "runbooks/billing-usage-redrive";
}

/// jobs-core handler for the mandatory periodic pending-usage scanner.
pub struct RedriveBillingUsageJobHandler<A> {
    reconciler: BillingReconciler<A>,
}

impl<A> RedriveBillingUsageJobHandler<A> {
    /// Creates a typed usage-redrive handler.
    #[must_use]
    pub const fn new(reconciler: BillingReconciler<A>) -> Self {
        Self { reconciler }
    }
}

impl<A: BillingProviderAdapter> TypedJobHandler<RedriveBillingUsageJob>
    for RedriveBillingUsageJobHandler<A>
{
    fn handle(
        &self,
        _job: RedriveBillingUsageJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            if context.is_cancelled() {
                return HandlerOutcome::Cancelled;
            }
            service_outcome(
                self.reconciler
                    .process_pending_usage(context.cancellation())
                    .await
                    .map(|_| ()),
            )
        })
    }
}

fn service_outcome(result: Result<(), BillingServiceError>) -> HandlerOutcome {
    match result {
        Ok(()) => HandlerOutcome::Succeeded,
        Err(BillingServiceError::Cancelled) => HandlerOutcome::Cancelled,
        Err(BillingServiceError::RetryableProvider | BillingServiceError::RetryableLocal) => {
            HandlerOutcome::Retryable(handler_failure("billing_retryable"))
        }
        Err(
            BillingServiceError::PermanentProvider
            | BillingServiceError::OutOfOrderEvent
            | BillingServiceError::EventConflict
            | BillingServiceError::SnapshotConflict
            | BillingServiceError::UsageConflict
            | BillingServiceError::UsageRejected
            | BillingServiceError::ProviderMismatch
            | BillingServiceError::PermanentLocal,
        ) => HandlerOutcome::Permanent(handler_failure("billing_permanent")),
    }
}

fn handler_failure(value: &str) -> HandlerFailure {
    let code = FailureCode::try_from(value).unwrap_or_else(|_| {
        FailureCode::try_from("billing_failure")
            .unwrap_or_else(|_| unreachable!("static billing failure code must be valid"))
    });
    HandlerFailure::new(code)
}
