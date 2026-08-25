use std::{fmt, sync::Arc, time::Duration};

use futures::future::BoxFuture;
use rsk_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, FailureCode, HandlerFailure,
    HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobPolicy, TypedJobHandler,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{DeliveryFailureClass, EmailError, MailSender, SendEmailRequest};

const SEND_EMAIL_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Required,
    5,
    1_000,
    60_000,
    2,
    Jitter::Full,
    60,
    32,
    Some(600),
    "email",
    5,
    7 * 24 * 60 * 60,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    900 * 1024,
) {
    Ok(policy) => policy,
    Err(_) => panic!("static email job policy must be valid"),
};

/// Typed at-least-once email job payload.
///
/// Rendered bodies are never serialized: the payload carries a validated template selection,
/// bounded context, and persisted client submission identifier. Diagnostics redact the request.
/// Its caller idempotency key must exactly match the jobs-core envelope key; it identifies the
/// effect but cannot make SMTP exactly-once.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendEmailJob {
    request: SendEmailRequest,
}

impl SendEmailJob {
    /// Creates a typed delivery payload.
    #[must_use]
    pub const fn new(request: SendEmailRequest) -> Self {
        Self { request }
    }

    /// Borrows the validated request.
    #[must_use]
    pub const fn request(&self) -> &SendEmailRequest {
        &self.request
    }

    /// Consumes the job into its delivery request.
    #[must_use]
    pub fn into_request(self) -> SendEmailRequest {
        self.request
    }
}

impl fmt::Debug for SendEmailJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendEmailJob")
            .field("request", &"[REDACTED]")
            .field("recipient_count", &self.request.recipient_count())
            .field("attachment_count", &self.request.attachment_count())
            .finish_non_exhaustive()
    }
}

impl Job for SendEmailJob {
    const NAME: &'static str = "email.send";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = SEND_EMAIL_POLICY;
    const METRICS_PREFIX: &'static str = "rsk_job_email_send";
    const RUNBOOK: &'static str = "runbooks/email-send";
}

/// jobs-core-compatible handler that enforces envelope/request identity and delivery cancellation.
pub struct SendEmailHandler {
    sender: Arc<dyn MailSender>,
}

impl SendEmailHandler {
    /// Creates a handler over the narrow mail-sender port.
    #[must_use]
    pub fn new(sender: Arc<dyn MailSender>) -> Self {
        Self { sender }
    }
}

impl TypedJobHandler<SendEmailJob> for SendEmailHandler {
    fn handle(&self, job: SendEmailJob, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let sender = Arc::clone(&self.sender);
        Box::pin(async move {
            if context.is_cancelled() {
                return HandlerOutcome::Cancelled;
            }
            let request = job.into_request();
            let Some(effect_key) = context.effect_identity().idempotency_key() else {
                return permanent("email_identity_missing");
            };
            if effect_key != request.idempotency_key() {
                return permanent("email_identity_mismatch");
            }

            let now = OffsetDateTime::now_utc();
            if context.deadline() <= now {
                return retryable("email_deadline");
            }
            let Ok(remaining) = Duration::try_from(context.deadline() - now) else {
                return retryable("email_deadline");
            };
            let cancellation = context.cancellation().clone();
            let result = tokio::select! {
                () = cancellation.cancelled() => return HandlerOutcome::Cancelled,
                result = tokio::time::timeout(remaining, sender.send(request)) => match result {
                    Ok(result) => result,
                    Err(_) => return retryable("email_deadline"),
                },
            };
            match result {
                Ok(_) => HandlerOutcome::Succeeded,
                Err(EmailError::Cancelled) => HandlerOutcome::Cancelled,
                Err(EmailError::Timeout | EmailError::Capacity | EmailError::AdmissionClosed) => {
                    retryable("email_unavailable")
                }
                Err(EmailError::Delivery(class)) if class.is_retryable() => {
                    retryable(delivery_retry_code(class))
                }
                Err(EmailError::Delivery(_)) => permanent("email_provider_rejected"),
                Err(_) => permanent("email_invalid"),
            }
        })
    }
}

impl fmt::Debug for SendEmailHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendEmailHandler")
            .field("sender", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

const fn delivery_retry_code(class: DeliveryFailureClass) -> &'static str {
    match class {
        DeliveryFailureClass::Transient => "email_transient",
        DeliveryFailureClass::Timeout => "email_timeout",
        _ => "email_unavailable",
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
        unreachable!("static email handler failure code must be valid")
    };
    HandlerFailure::new(code)
}
