use std::{fmt, sync::Arc, time::Duration};

use futures::future::BoxFuture;
use metrics::counter;
use rsk_auth_core::{SubjectId, TenantId as AuthTenantId};
use rsk_email::{ClientMessageId, DeliveryFailureClass, EmailError, MailSender, SendReceipt};
use rsk_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, FailureCode, HandlerFailure,
    HandlerOutcome, IdempotencyKey, IdempotencyRequirement, Jitter, Job, JobEnvelope,
    JobEnvelopeOptions, JobPolicy, TenantId, TypedJobHandler,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    ClaimOutcome, DeliveryId, DeliveryStatus, Locale, NotificationError,
    PostgresNotificationRepository, ProviderScope, repository::DeliveryFence,
};

const SEND_NOTIFICATION_EMAIL_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Required,
    8,
    1_000,
    60_000,
    2,
    Jitter::Full,
    30,
    32,
    Some(600),
    "notifications",
    5,
    7 * 24 * 60 * 60,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    16 * 1024,
) {
    Ok(policy) => policy,
    Err(_) => panic!("static notification email job policy must be valid"),
};

/// Minimal immutable durable notification-email payload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEmailJob {
    delivery_id: DeliveryId,
    template: rsk_email::TemplateName,
    template_version: u32,
    recipient_id: SubjectId,
    locale: Locale,
}

impl NotificationEmailJob {
    /// Creates the v1 payload persisted in the notification outbox.
    #[must_use]
    pub const fn new(
        delivery_id: DeliveryId,
        template: rsk_email::TemplateName,
        template_version: u32,
        recipient_id: SubjectId,
        locale: Locale,
    ) -> Self {
        Self {
            delivery_id,
            template,
            template_version,
            recipient_id,
            locale,
        }
    }

    /// Delivery identity.
    #[must_use]
    pub const fn delivery_id(&self) -> DeliveryId {
        self.delivery_id
    }

    /// Historical template key.
    #[must_use]
    pub const fn template(&self) -> &rsk_email::TemplateName {
        &self.template
    }

    /// Historical template version.
    #[must_use]
    pub const fn template_version(&self) -> u32 {
        self.template_version
    }

    /// Recipient identity.
    #[must_use]
    pub const fn recipient_id(&self) -> SubjectId {
        self.recipient_id
    }

    /// Selected locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }
}

impl fmt::Debug for NotificationEmailJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationEmailJob")
            .field("delivery_id", &self.delivery_id)
            .field("template", &"[REDACTED]")
            .field("template_version", &self.template_version)
            .field("recipient_id", &self.recipient_id)
            .field("locale", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Job for NotificationEmailJob {
    const NAME: &'static str = "notifications.send_email";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = SEND_NOTIFICATION_EMAIL_POLICY;
    const METRICS_PREFIX: &'static str = "rsk_notifications_send_email";
    const RUNBOOK: &'static str = "runbooks/notifications-send-email";
}

pub(crate) fn effect_key(delivery_id: DeliveryId) -> Result<IdempotencyKey, NotificationError> {
    IdempotencyKey::try_from(format!("notification:{delivery_id}"))
        .map_err(|_| NotificationError::InvalidJobEnvelope)
}

pub(crate) fn build_envelope(
    job: NotificationEmailJob,
    tenant_id: AuthTenantId,
    correlation_id: uuid::Uuid,
    causation_id: Option<uuid::Uuid>,
    not_before: OffsetDateTime,
) -> Result<JobEnvelope<NotificationEmailJob>, NotificationError> {
    let tenant = TenantId::try_from(tenant_id.to_string())
        .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    let key = effect_key(job.delivery_id())?;
    let mut options = JobEnvelopeOptions::new(correlation_id)
        .map_err(|_| NotificationError::InvalidJobEnvelope)?
        .with_tenant(tenant)
        .with_not_before(not_before)
        .with_idempotency_key(key);
    if let Some(causation_id) = causation_id {
        options = options
            .with_causation(causation_id)
            .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    }
    JobEnvelope::new(job, options).map_err(|_| NotificationError::InvalidJobEnvelope)
}

/// Durable handler that rechecks preference at send time and persists every outcome.
pub struct NotificationEmailHandler {
    repository: PostgresNotificationRepository,
    sender: Arc<dyn MailSender>,
    provider_scope: ProviderScope,
}

impl NotificationEmailHandler {
    /// Creates a handler over PostgreSQL-authoritative state and one provider account namespace.
    #[must_use]
    pub fn new(
        repository: PostgresNotificationRepository,
        sender: Arc<dyn MailSender>,
        provider_scope: ProviderScope,
    ) -> Self {
        Self {
            repository,
            sender,
            provider_scope,
        }
    }
}

impl TypedJobHandler<NotificationEmailJob> for NotificationEmailHandler {
    fn handle(
        &self,
        job: NotificationEmailJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let repository = self.repository.clone();
        let sender = Arc::clone(&self.sender);
        let provider_scope = self.provider_scope.clone();
        Box::pin(async move {
            let preparation = match prepare_claim(&repository, &job, &context).await {
                Ok(preparation) => preparation,
                Err(outcome) => return outcome,
            };
            let ClaimPreparation {
                tenant_id,
                expected_key,
                final_attempt,
            } = preparation;

            let Ok(claimed) = repository.claim_for_send(tenant_id, &job, &context).await else {
                return retryable("notification_state_unavailable");
            };
            let effect = match claimed {
                ClaimOutcome::Claimed(effect) => effect,
                ClaimOutcome::Busy => return retryable("notification_busy"),
                ClaimOutcome::Terminal(DeliveryStatus::Cancelled) => {
                    return HandlerOutcome::Succeeded;
                }
                ClaimOutcome::Terminal(DeliveryStatus::PermanentFailed) => {
                    return permanent("notification_permanent");
                }
                ClaimOutcome::Terminal(_) => return HandlerOutcome::Succeeded,
            };
            let request = effect.request;
            let fence = effect.fence;
            let client_message_id = effect.client_message_id;

            let after_claim = OffsetDateTime::now_utc();
            if context.deadline() <= after_claim {
                return record_attempt_failure(
                    &repository,
                    &fence,
                    "notification_deadline",
                    final_attempt,
                )
                .await;
            }
            let Ok(remaining) = Duration::try_from(context.deadline() - after_claim) else {
                return record_attempt_failure(
                    &repository,
                    &fence,
                    "notification_deadline",
                    final_attempt,
                )
                .await;
            };
            let cancellation = context.cancellation().clone();
            let result = tokio::select! {
                () = cancellation.cancelled() => {
                    return release_cancelled(&repository, &fence).await;
                }
                result = tokio::time::timeout(remaining, sender.send(request)) => {
                    let Ok(result) = result else {
                        return record_attempt_failure(
                            &repository,
                            &fence,
                            "notification_deadline",
                            final_attempt,
                        )
                        .await;
                    };
                    result
                },
            };

            let outcome = record_send_result(
                &repository,
                &fence,
                &expected_key,
                &client_message_id,
                &provider_scope,
                result,
                final_attempt,
            )
            .await;
            counter!("rsk_notifications_delivery_total", "channel" => "email", "outcome" => outcome_label(&outcome)).increment(1);
            outcome
        })
    }
}

struct ClaimPreparation {
    tenant_id: AuthTenantId,
    expected_key: IdempotencyKey,
    final_attempt: bool,
}

async fn prepare_claim(
    repository: &PostgresNotificationRepository,
    job: &NotificationEmailJob,
    context: &DeliveryContext,
) -> Result<ClaimPreparation, HandlerOutcome> {
    let Some(tenant) = context.tenant_id() else {
        return Err(permanent("notification_tenant_missing"));
    };
    let tenant_id = tenant
        .as_str()
        .parse::<AuthTenantId>()
        .map_err(|_| permanent("notification_tenant_invalid"))?;
    let expected_key =
        effect_key(job.delivery_id()).map_err(|_| permanent("notification_identity_invalid"))?;
    if context.effect_identity().idempotency_key() != Some(&expected_key) {
        return Err(permanent("notification_identity_mismatch"));
    }
    let final_attempt = context.attempt().get() >= NotificationEmailJob::POLICY.max_attempts();
    if context.is_cancelled() {
        return Err(HandlerOutcome::Cancelled);
    }
    if context.deadline() <= OffsetDateTime::now_utc() {
        if final_attempt {
            return match repository
                .record_unclaimed_permanent(
                    tenant_id,
                    job.delivery_id(),
                    "notification_retry_exhausted",
                )
                .await
            {
                Ok(()) => Err(permanent("notification_retry_exhausted")),
                Err(_) => Err(retryable("notification_state_unavailable")),
            };
        }
        let _ = repository
            .record_unclaimed_retryable(tenant_id, job.delivery_id(), "notification_deadline")
            .await;
        return Err(retryable("notification_deadline"));
    }
    Ok(ClaimPreparation {
        tenant_id,
        expected_key,
        final_attempt,
    })
}

async fn record_send_result(
    repository: &PostgresNotificationRepository,
    fence: &DeliveryFence,
    expected_key: &IdempotencyKey,
    client_message_id: &ClientMessageId,
    provider_scope: &ProviderScope,
    result: Result<SendReceipt, EmailError>,
    final_attempt: bool,
) -> HandlerOutcome {
    match result {
        Ok(receipt) => {
            if receipt.idempotency_key() != expected_key
                || receipt.client_message_id() != client_message_id
            {
                match repository
                    .record_permanent(fence, "notification_receipt_mismatch")
                    .await
                {
                    Ok(()) => permanent("notification_receipt_mismatch"),
                    Err(_) => retryable("notification_state_unavailable"),
                }
            } else if repository
                .record_accepted(fence, &receipt, provider_scope)
                .await
                .is_ok()
            {
                HandlerOutcome::Succeeded
            } else {
                retryable("notification_state_unavailable")
            }
        }
        Err(EmailError::Cancelled) => release_cancelled(repository, fence).await,
        Err(error) => {
            record_email_failure(
                repository,
                fence,
                classify_email_error(error),
                final_attempt,
            )
            .await
        }
    }
}

async fn record_email_failure(
    repository: &PostgresNotificationRepository,
    fence: &DeliveryFence,
    disposition: EmailDisposition,
    final_attempt: bool,
) -> HandlerOutcome {
    match disposition {
        EmailDisposition::Retryable(code) => {
            record_attempt_failure(repository, fence, code, final_attempt).await
        }
        EmailDisposition::Permanent(code) => match repository.record_permanent(fence, code).await {
            Ok(()) => permanent(code),
            Err(_) => retryable("notification_state_unavailable"),
        },
        EmailDisposition::Cancelled => release_cancelled(repository, fence).await,
    }
}

async fn release_cancelled(
    repository: &PostgresNotificationRepository,
    fence: &DeliveryFence,
) -> HandlerOutcome {
    let _ = repository
        .record_retryable(fence, "notification_cancelled")
        .await;
    HandlerOutcome::Cancelled
}

async fn record_attempt_failure(
    repository: &PostgresNotificationRepository,
    fence: &DeliveryFence,
    code: &'static str,
    final_attempt: bool,
) -> HandlerOutcome {
    if final_attempt {
        match repository
            .record_permanent(fence, "notification_retry_exhausted")
            .await
        {
            Ok(()) => permanent("notification_retry_exhausted"),
            Err(_) => retryable("notification_state_unavailable"),
        }
    } else {
        let _ = repository.record_retryable(fence, code).await;
        retryable(code)
    }
}

impl fmt::Debug for NotificationEmailHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationEmailHandler")
            .field("repository", &self.repository)
            .field("sender", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmailDisposition {
    Retryable(&'static str),
    Permanent(&'static str),
    Cancelled,
}

pub(crate) const fn classify_email_error(error: EmailError) -> EmailDisposition {
    match error {
        EmailError::Cancelled => EmailDisposition::Cancelled,
        EmailError::Timeout | EmailError::Capacity | EmailError::AdmissionClosed => {
            EmailDisposition::Retryable("notification_email_unavailable")
        }
        EmailError::Delivery(class) if class.is_retryable() => {
            EmailDisposition::Retryable(delivery_retry_code(class))
        }
        EmailError::Delivery(_) => EmailDisposition::Permanent("notification_email_rejected"),
        _ => EmailDisposition::Permanent("notification_email_invalid"),
    }
}

const fn delivery_retry_code(class: DeliveryFailureClass) -> &'static str {
    match class {
        DeliveryFailureClass::Transient => "notification_email_transient",
        DeliveryFailureClass::Timeout => "notification_email_timeout",
        _ => "notification_email_unavailable",
    }
}

fn outcome_label(outcome: &HandlerOutcome) -> &'static str {
    match outcome {
        HandlerOutcome::Succeeded => "succeeded",
        HandlerOutcome::Retryable(_) => "retryable",
        HandlerOutcome::Permanent(_) => "permanent",
        HandlerOutcome::Cancelled => "cancelled",
    }
}

fn retryable(code: &'static str) -> HandlerOutcome {
    HandlerOutcome::Retryable(handler_failure(code))
}

fn permanent(code: &'static str) -> HandlerOutcome {
    HandlerOutcome::Permanent(handler_failure(code))
}

fn handler_failure(code: &'static str) -> HandlerFailure {
    let Ok(code) = FailureCode::try_from(code) else {
        unreachable!("static notification failure code must be valid")
    };
    HandlerFailure::new(code)
}

#[cfg(test)]
mod tests {
    use super::{EmailDisposition, classify_email_error};
    use rsk_email::{DeliveryFailureClass, EmailError};

    #[test]
    fn email_error_mapping_preserves_retry_permanent_and_cancel_contract() {
        assert_eq!(
            classify_email_error(EmailError::Delivery(DeliveryFailureClass::Transient)),
            EmailDisposition::Retryable("notification_email_transient")
        );
        assert_eq!(
            classify_email_error(EmailError::Delivery(DeliveryFailureClass::Permanent)),
            EmailDisposition::Permanent("notification_email_rejected")
        );
        assert_eq!(
            classify_email_error(EmailError::Cancelled),
            EmailDisposition::Cancelled
        );
    }
}
