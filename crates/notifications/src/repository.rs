use std::{fmt, time::Duration};

use metrics::{counter, histogram};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_core::CausationId;
use omnius_email::{
    ClientMessageId, DisplayName, EmailAddress, EmailSubject, MailboxAddress, ProviderBounceClass,
    ProviderDeliveryEvent, ProviderDeliveryEventKind, ProviderMessageId, RecipientSet,
    SendEmailRequest, SendReceipt, TemplateContext, TemplateName,
};
use omnius_jobs_core::{DeliveryContext, EncodedJobEnvelope, IdempotencyKey, JobId, QueueName};
use omnius_postgres::PostgresPool;
use serde_json::Value;
use sqlx::{Connection as _, Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    DeliveryId, DeliveryMode, DeliveryRecord, DeliveryStatus, Locale, NotificationChannel,
    NotificationEmailJob, NotificationError, NotificationRequest, PreferenceCategory,
    ProviderEventOutcome, ProviderScope, build_envelope, effect_key, error::map_sqlx,
};

const MAX_DISPATCH_BATCH: u16 = 100;
const MAX_DIGEST_CONTEXT_BYTES: i64 = 48 * 1024;
const MAX_LEASE_SECONDS: u64 = 5 * 60;

/// Result of durably recording one channel intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SchedulePersistence {
    pub record: DeliveryRecord,
    pub inserted: bool,
    pub has_pending_outbox: bool,
}

struct SchedulePlan {
    digest_bucket_id: Option<Uuid>,
    dedupe_bucket_started_at: OffsetDateTime,
    initial_status: DeliveryStatus,
    available_at: OffsetDateTime,
}

/// One fenced PostgreSQL job-outbox claim.
pub(crate) struct PendingOutbox {
    pub delivery_id: DeliveryId,
    pub tenant_id: TenantId,
    pub job_id: JobId,
    pub lease_token: Uuid,
    pub envelope: EncodedJobEnvelope,
}

impl fmt::Debug for PendingOutbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingOutbox")
            .field("delivery_id", &self.delivery_id)
            .field("tenant_id", &self.tenant_id)
            .field("job_id", &self.job_id)
            .field("lease_token", &self.lease_token)
            .field("envelope", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Stable send-attempt fence retained after the request is moved into `MailSender`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeliveryFence {
    pub tenant_id: TenantId,
    pub delivery_id: DeliveryId,
    pub lease_token: Uuid,
}

/// Claimed exact email effect.
pub(crate) struct ClaimedEmailEffect {
    pub request: SendEmailRequest,
    pub fence: DeliveryFence,
    pub client_message_id: ClientMessageId,
}

impl fmt::Debug for ClaimedEmailEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedEmailEffect")
            .field("request", &"[REDACTED]")
            .field("fence", &self.fence)
            .field("client_message_id", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Result of a tenant-fenced send claim.
#[derive(Debug)]
pub(crate) enum ClaimOutcome {
    Claimed(Box<ClaimedEmailEffect>),
    Busy,
    Terminal(DeliveryStatus),
}

/// PostgreSQL-authoritative notification state and transactional job outbox.
#[derive(Clone)]
pub struct PostgresNotificationRepository {
    pool: PostgresPool,
}

impl PostgresNotificationRepository {
    /// Creates a repository using the managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    pub(crate) const fn pool(&self) -> &PostgresPool {
        &self.pool
    }

    /// Loads one delivery only inside its tenant fence.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::NotFound`] when the delivery is outside the supplied tenant
    /// fence, or another [`NotificationError`] for unavailable or inconsistent persistence.
    pub async fn get_delivery(
        &self,
        tenant_id: TenantId,
        delivery_id: DeliveryId,
    ) -> Result<DeliveryRecord, NotificationError> {
        let mut connection = self.pool.acquire().await?;
        let row = sqlx::query(
            "SELECT id, tenant_id, recipient_id, channel, status, attempt_count, \
                    template_version, created_at, updated_at \
             FROM deliveries WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(delivery_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx(&error))?
        .ok_or(NotificationError::NotFound)?;
        delivery_record(&row)
    }

    /// Applies one verified asynchronous provider event inside its tenant fence.
    ///
    /// The provider event identity and resulting delivery state are committed atomically. A
    /// repeated event identity is reported as a duplicate without applying the transition again.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::NotFound`] when no delivery matches the tenant, provider scope,
    /// and provider message identity, or another [`NotificationError`] for unavailable or
    /// inconsistent persistence.
    pub async fn record_provider_event(
        &self,
        tenant_id: TenantId,
        provider_scope: &ProviderScope,
        event: &ProviderDeliveryEvent,
    ) -> Result<ProviderEventOutcome, NotificationError> {
        let occurred_at = provider_event_time(event.occurred_at_unix_ms())?;
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let outcome = apply_provider_event(
            &mut transaction,
            tenant_id,
            provider_scope,
            event,
            occurred_at,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        counter!(
            "notifications.provider_events_total",
            "outcome" => provider_event_outcome_label(outcome),
            "status" => provider_event_outcome_status(outcome).as_str()
        )
        .increment(1);
        Ok(outcome)
    }

    pub(crate) async fn schedule_channel(
        &self,
        request: &NotificationRequest,
        channel: NotificationChannel,
    ) -> Result<SchedulePersistence, NotificationError> {
        let started = std::time::Instant::now();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| map_sqlx(&error))?;
        let plan = prepare_schedule_plan(&mut transaction, request, channel, now).await?;
        let (delivery_id, inserted) =
            insert_delivery(&mut transaction, request, channel, &plan, now).await?;
        let outcome = if let Some(row) = inserted {
            finalize_new_delivery(&mut transaction, request, channel, delivery_id, &plan, now)
                .await?;
            SchedulePersistence {
                record: delivery_record(&row)?,
                inserted: true,
                has_pending_outbox: plan.digest_bucket_id.is_none(),
            }
        } else {
            load_duplicate_delivery(&mut transaction, request, channel, &plan).await?
        };
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        let result = if outcome.inserted {
            if plan.digest_bucket_id.is_some() {
                "digest"
            } else {
                "pending"
            }
        } else {
            "duplicate"
        };
        counter!("omnius_notifications_schedule_total", "channel" => "email", "result" => result)
            .increment(1);
        histogram!("omnius_notifications_schedule_duration_seconds", "result" => result)
            .record(started.elapsed().as_secs_f64());
        Ok(outcome)
    }

    /// Releases a bounded number of due digest buckets into the durable job outbox.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::InvalidRequest`] when `limit` is zero or exceeds 100, or
    /// another [`NotificationError`] when a due digest cannot be represented or persisted.
    pub async fn release_due_digests(&self, limit: u16) -> Result<u16, NotificationError> {
        if limit == 0 || limit > MAX_DISPATCH_BATCH {
            return Err(NotificationError::InvalidRequest);
        }
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| map_sqlx(&error))?;
        let rows = sqlx::query(
            "SELECT b.id AS bucket_id, b.leader_delivery_id, d.tenant_id, d.recipient_id, \
                    d.template_name, d.template_version, d.locale, d.correlation_id, d.causation_id \
             FROM notification_digest_buckets b \
             JOIN deliveries d ON d.id = b.leader_delivery_id \
             WHERE b.released_at IS NULL AND b.bucket_ends_at <= $1 \
             ORDER BY b.bucket_ends_at, b.id \
             LIMIT $2 FOR UPDATE OF b SKIP LOCKED",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
        for row in &rows {
            release_digest_bucket(&mut transaction, row, now).await?;
        }
        let released = u16::try_from(rows.len()).map_err(|_| NotificationError::InvalidState)?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        Ok(released)
    }

    pub(crate) async fn claim_pending_outbox(
        &self,
        limit: u16,
        lease_duration: Duration,
    ) -> Result<Vec<PendingOutbox>, NotificationError> {
        if limit == 0
            || limit > MAX_DISPATCH_BATCH
            || lease_duration.is_zero()
            || lease_duration.as_secs() > MAX_LEASE_SECONDS
        {
            return Err(NotificationError::InvalidRequest);
        }
        let mut connection = self.pool.acquire().await?;
        let lease_token = Uuid::now_v7();
        let lease_micros = postgres_interval_micros(lease_duration)?;
        let rows = sqlx::query(
            "WITH candidates AS ( \
                SELECT delivery_id FROM notification_job_outbox \
                WHERE dispatched_at IS NULL AND available_at <= clock_timestamp() \
                  AND (lease_token IS NULL OR lease_expires_at <= clock_timestamp()) \
                ORDER BY available_at, delivery_id LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) UPDATE notification_job_outbox o \
               SET lease_token = $2, lease_expires_at = clock_timestamp() + ($3::bigint * interval '1 microsecond'), \
                   dispatch_attempts = CASE WHEN dispatch_attempts < 2147483647 \
                       THEN dispatch_attempts + 1 ELSE dispatch_attempts END, \
                   updated_at = clock_timestamp() \
             FROM candidates c WHERE o.delivery_id = c.delivery_id \
             RETURNING o.delivery_id, o.tenant_id, o.job_id, o.envelope",
        )
        .bind(i64::from(limit))
        .bind(lease_token)
        .bind(lease_micros)
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_sqlx(&error))?;
        rows.iter()
            .map(|row| pending_outbox(row, lease_token))
            .collect()
    }

    pub(crate) async fn claim_delivery_outbox(
        &self,
        tenant_id: TenantId,
        delivery_id: DeliveryId,
        lease_duration: Duration,
    ) -> Result<Option<PendingOutbox>, NotificationError> {
        if lease_duration.is_zero() || lease_duration.as_secs() > MAX_LEASE_SECONDS {
            return Err(NotificationError::InvalidRequest);
        }
        let mut connection = self.pool.acquire().await?;
        let lease_token = Uuid::now_v7();
        let lease_micros = postgres_interval_micros(lease_duration)?;
        let row = sqlx::query(
            "UPDATE notification_job_outbox SET \
                lease_token = $3, lease_expires_at = clock_timestamp() + ($4::bigint * interval '1 microsecond'), \
                dispatch_attempts = CASE WHEN dispatch_attempts < 2147483647 \
                    THEN dispatch_attempts + 1 ELSE dispatch_attempts END, \
                updated_at = clock_timestamp() \
             WHERE delivery_id = $1 AND tenant_id = $2 AND dispatched_at IS NULL \
               AND available_at <= clock_timestamp() \
               AND (lease_token IS NULL OR lease_expires_at <= clock_timestamp()) \
             RETURNING delivery_id, tenant_id, job_id, envelope",
        )
        .bind(delivery_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(lease_token)
        .bind(lease_micros)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx(&error))?;
        row.as_ref()
            .map(|row| pending_outbox(row, lease_token))
            .transpose()
    }

    pub(crate) async fn mark_dispatched(
        &self,
        pending: &PendingOutbox,
        accepted_job_id: JobId,
        accepted_at: OffsetDateTime,
    ) -> Result<(), NotificationError> {
        if pending.job_id != accepted_job_id {
            return Err(NotificationError::InvalidState);
        }
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let result = sqlx::query(
            "UPDATE notification_job_outbox SET dispatched_at = $4, lease_token = NULL, \
                    lease_expires_at = NULL, last_error_code = NULL, updated_at = $4 \
             WHERE delivery_id = $1 AND tenant_id = $2 AND lease_token = $3 \
               AND dispatched_at IS NULL",
        )
        .bind(pending.delivery_id.as_uuid())
        .bind(pending.tenant_id.as_uuid())
        .bind(pending.lease_token)
        .bind(accepted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
        if result.rows_affected() != 1 {
            return Err(NotificationError::InvalidState);
        }
        sqlx::query(
            "UPDATE deliveries SET status = 'queued', last_job_id = $3, enqueued_at = $4, \
                    updated_at = $4 \
             WHERE id = $1 AND tenant_id = $2 AND status = 'pending_dispatch'",
        )
        .bind(pending.delivery_id.as_uuid())
        .bind(pending.tenant_id.as_uuid())
        .bind(accepted_job_id.as_uuid())
        .bind(accepted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        Ok(())
    }

    pub(crate) async fn release_outbox(
        &self,
        pending: &PendingOutbox,
        error_code: &'static str,
    ) -> Result<(), NotificationError> {
        let mut connection = self.pool.acquire().await?;
        sqlx::query(
            "UPDATE notification_job_outbox SET lease_token = NULL, lease_expires_at = NULL, \
                    available_at = clock_timestamp() + ( \
                        LEAST(300, (1::bigint << LEAST(dispatch_attempts, 8))) * interval '1 second' \
                    ), last_error_code = $4, updated_at = clock_timestamp() \
             WHERE delivery_id = $1 AND tenant_id = $2 AND lease_token = $3 \
               AND dispatched_at IS NULL",
        )
        .bind(pending.delivery_id.as_uuid())
        .bind(pending.tenant_id.as_uuid())
        .bind(pending.lease_token)
        .bind(error_code)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx(&error))?;
        Ok(())
    }

    pub(crate) async fn recover_stale_deliveries(
        &self,
        limit: u16,
    ) -> Result<u16, NotificationError> {
        if limit == 0 || limit > MAX_DISPATCH_BATCH {
            return Err(NotificationError::InvalidRequest);
        }
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| map_sqlx(&error))?;
        let rows = sqlx::query(
            "SELECT * FROM deliveries \
             WHERE (status = 'sending' AND send_lease_expires_at <= $1) \
                OR (status = 'retryable' AND updated_at <= $1 - interval '5 minutes') \
             ORDER BY updated_at, id FOR UPDATE SKIP LOCKED LIMIT $2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
        for row in &rows {
            recover_delivery(&mut transaction, row, now).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        u16::try_from(rows.len()).map_err(|_| NotificationError::InvalidState)
    }

    pub(crate) async fn claim_for_send(
        &self,
        tenant_id: TenantId,
        job: &NotificationEmailJob,
        context: &DeliveryContext,
    ) -> Result<ClaimOutcome, NotificationError> {
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let row =
            sqlx::query("SELECT * FROM deliveries WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
                .bind(tenant_id.as_uuid())
                .bind(job.delivery_id().as_uuid())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| map_sqlx(&error))?
                .ok_or(NotificationError::NotFound)?;
        validate_job_identity(&row, job, context)?;
        let status: DeliveryStatus = row
            .try_get::<String, _>("status")
            .map_err(|_| NotificationError::InvalidState)?
            .parse()?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| map_sqlx(&error))?;
        let early = if status.is_terminal() {
            Some(ClaimOutcome::Terminal(status))
        } else if let Some(outcome) = unavailable_claim_outcome(&row, status, now)? {
            Some(outcome)
        } else {
            optional_preference_outcome(&mut transaction, &row, tenant_id, job, now).await?
        };
        if let Some(outcome) = early {
            transaction
                .commit()
                .await
                .map_err(|error| map_sqlx(&error))?;
            return Ok(outcome);
        }
        let effect =
            claim_email_effect(&mut transaction, &row, tenant_id, job, context, now).await?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        Ok(ClaimOutcome::Claimed(Box::new(effect)))
    }

    pub(crate) async fn record_accepted(
        &self,
        fence: &DeliveryFence,
        receipt: &SendReceipt,
        provider_scope: &ProviderScope,
    ) -> Result<(), NotificationError> {
        let provider_message_id = receipt.provider_message_id().map(ProviderMessageId::as_str);
        self.finish_claim(
            fence,
            "accepted",
            None,
            provider_message_id.map(|_| provider_scope.as_str()),
            provider_message_id,
            false,
        )
        .await
    }

    pub(crate) async fn record_retryable(
        &self,
        fence: &DeliveryFence,
        code: &'static str,
    ) -> Result<(), NotificationError> {
        self.finish_claim(fence, "retryable", Some(code), None, None, false)
            .await
    }

    pub(crate) async fn record_permanent(
        &self,
        fence: &DeliveryFence,
        code: &'static str,
    ) -> Result<(), NotificationError> {
        self.finish_claim(fence, "permanent_failed", Some(code), None, None, true)
            .await
    }

    async fn finish_claim(
        &self,
        fence: &DeliveryFence,
        status: &'static str,
        code: Option<&'static str>,
        provider_scope: Option<&str>,
        provider_message_id: Option<&str>,
        terminal: bool,
    ) -> Result<(), NotificationError> {
        let mut connection = self.pool.acquire().await?;
        let result = sqlx::query(
            "UPDATE deliveries SET status = $4, last_failure_code = $5, \
                    provider_scope = COALESCE($6, provider_scope), \
                    provider_message_id = COALESCE($7, provider_message_id), \
                    accepted_at = CASE WHEN $4 = 'accepted' THEN clock_timestamp() ELSE accepted_at END, \
                    final_at = CASE WHEN $8 THEN clock_timestamp() ELSE final_at END, \
                    send_lease_token = NULL, send_lease_expires_at = NULL, updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND send_lease_token = $3 AND status = 'sending'",
        )
        .bind(fence.tenant_id.as_uuid())
        .bind(fence.delivery_id.as_uuid())
        .bind(fence.lease_token)
        .bind(status)
        .bind(code)
        .bind(provider_scope)
        .bind(provider_message_id)
        .bind(terminal)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx(&error))?;
        if result.rows_affected() != 1 {
            return Err(NotificationError::InvalidState);
        }
        Ok(())
    }

    pub(crate) async fn record_unclaimed_retryable(
        &self,
        tenant_id: TenantId,
        delivery_id: DeliveryId,
        code: &'static str,
    ) -> Result<(), NotificationError> {
        let mut connection = self.pool.acquire().await?;
        sqlx::query(
            "UPDATE deliveries SET status = 'retryable', last_failure_code = $3, updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND status = 'queued'",
        )
        .bind(tenant_id.as_uuid()).bind(delivery_id.as_uuid()).bind(code)
        .execute(&mut *connection).await.map_err(|error| map_sqlx(&error))?;
        Ok(())
    }

    pub(crate) async fn record_unclaimed_permanent(
        &self,
        tenant_id: TenantId,
        delivery_id: DeliveryId,
        code: &'static str,
    ) -> Result<(), NotificationError> {
        let mut connection = self.pool.acquire().await?;
        let result = sqlx::query(
            "UPDATE deliveries SET status = 'permanent_failed', last_failure_code = $3, \
                    final_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND status IN ('queued', 'retryable')",
        )
        .bind(tenant_id.as_uuid())
        .bind(delivery_id.as_uuid())
        .bind(code)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx(&error))?;
        if result.rows_affected() != 1 {
            return Err(NotificationError::InvalidState);
        }
        Ok(())
    }
}

async fn apply_provider_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    provider_scope: &ProviderScope,
    event: &ProviderDeliveryEvent,
    occurred_at: OffsetDateTime,
) -> Result<ProviderEventOutcome, NotificationError> {
    let row = sqlx::query(
        "SELECT id, status FROM deliveries \
         WHERE tenant_id = $1 AND provider_scope = $2 AND provider_message_id = $3 FOR UPDATE",
    )
    .bind(tenant_id.as_uuid())
    .bind(provider_scope.as_str())
    .bind(event.provider_message_id().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?
    .ok_or(NotificationError::NotFound)?;
    let delivery_id: Uuid = row
        .try_get("id")
        .map_err(|_| NotificationError::InvalidState)?;
    let current: DeliveryStatus = row
        .try_get::<String, _>("status")
        .map_err(|_| NotificationError::InvalidState)?
        .parse()?;
    if !matches!(
        current,
        DeliveryStatus::Accepted
            | DeliveryStatus::Delivered
            | DeliveryStatus::Bounced
            | DeliveryStatus::Complained
    ) {
        return Err(NotificationError::InvalidState);
    }
    let (target, kind, bounce_class, terminalizes) = provider_event_target(event.kind());
    let applied = current == DeliveryStatus::Accepted && terminalizes;
    let resulting_status = if applied { target } else { current };
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO notification_provider_events \
             (id, tenant_id, delivery_id, event_id, provider_scope, provider_message_id, kind, \
              bounce_class, occurred_at, applied, resulting_status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (provider_scope, event_id) DO NOTHING RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id.as_uuid())
    .bind(delivery_id)
    .bind(event.event_id().as_str())
    .bind(provider_scope.as_str())
    .bind(event.provider_message_id().as_str())
    .bind(kind)
    .bind(bounce_class)
    .bind(occurred_at)
    .bind(applied)
    .bind(resulting_status.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if inserted.is_none() {
        return duplicate_provider_event(transaction, tenant_id, provider_scope, event).await;
    }
    if !applied {
        return Ok(ProviderEventOutcome::Ignored(resulting_status));
    }
    let result = sqlx::query(
        "UPDATE deliveries SET status = $3, \
                delivered_at = CASE WHEN $3 = 'delivered' THEN $4 ELSE delivered_at END, \
                final_at = clock_timestamp(), updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'accepted'",
    )
    .bind(tenant_id.as_uuid())
    .bind(delivery_id)
    .bind(target.as_str())
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if result.rows_affected() != 1 {
        return Err(NotificationError::InvalidState);
    }
    Ok(ProviderEventOutcome::Applied(target))
}

async fn duplicate_provider_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    provider_scope: &ProviderScope,
    event: &ProviderDeliveryEvent,
) -> Result<ProviderEventOutcome, NotificationError> {
    let row = sqlx::query(
        "SELECT tenant_id, provider_message_id, kind, bounce_class, occurred_at, resulting_status \
         FROM notification_provider_events WHERE provider_scope = $1 AND event_id = $2",
    )
    .bind(provider_scope.as_str())
    .bind(event.event_id().as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    let stored_tenant_id: Uuid = row
        .try_get("tenant_id")
        .map_err(|_| NotificationError::InvalidState)?;
    let provider_message_id: String = row
        .try_get("provider_message_id")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_kind: String = row
        .try_get("kind")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_bounce_class: Option<String> = row
        .try_get("bounce_class")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_occurred_at: OffsetDateTime = row
        .try_get("occurred_at")
        .map_err(|_| NotificationError::InvalidState)?;
    let (_, kind, bounce_class, _) = provider_event_target(event.kind());
    if stored_tenant_id != tenant_id.as_uuid()
        || provider_message_id != event.provider_message_id().as_str()
        || stored_kind != kind
        || stored_bounce_class.as_deref() != bounce_class
        || stored_occurred_at != provider_event_time(event.occurred_at_unix_ms())?
    {
        return Err(NotificationError::InvalidState);
    }
    let status = row
        .try_get::<String, _>("resulting_status")
        .map_err(|_| NotificationError::InvalidState)?
        .parse()?;
    Ok(ProviderEventOutcome::Duplicate(status))
}

const fn provider_event_target(
    kind: ProviderDeliveryEventKind,
) -> (DeliveryStatus, &'static str, Option<&'static str>, bool) {
    match kind {
        ProviderDeliveryEventKind::Delivered => {
            (DeliveryStatus::Delivered, "delivered", None, true)
        }
        ProviderDeliveryEventKind::Bounce { classification } => match classification {
            ProviderBounceClass::Transient => {
                (DeliveryStatus::Accepted, "bounce", Some("transient"), false)
            }
            ProviderBounceClass::Permanent => {
                (DeliveryStatus::Bounced, "bounce", Some("permanent"), true)
            }
            ProviderBounceClass::Undetermined => (
                DeliveryStatus::Accepted,
                "bounce",
                Some("undetermined"),
                false,
            ),
        },
        ProviderDeliveryEventKind::Complaint => {
            (DeliveryStatus::Complained, "complaint", None, true)
        }
    }
}

fn provider_event_time(unix_ms: i64) -> Result<OffsetDateTime, NotificationError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_ms) * 1_000_000)
        .map_err(|_| NotificationError::InvalidRequest)
}

async fn recover_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    row: &sqlx::postgres::PgRow,
    now: OffsetDateTime,
) -> Result<(), NotificationError> {
    let (delivery_id, tenant_id, job) = delivery_job_from_row(row)?;
    let envelope = build_envelope(
        job,
        tenant_id,
        row.try_get("correlation_id")
            .map_err(|_| NotificationError::InvalidState)?,
        row.try_get("causation_id")
            .map_err(|_| NotificationError::InvalidState)?,
        now,
    )?;
    let encoded = envelope
        .encode()
        .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    let outbox = sqlx::query(
        "UPDATE notification_job_outbox SET job_id = $3, envelope = $4, available_at = $5, \
                dispatch_attempts = 0, lease_token = NULL, lease_expires_at = NULL, \
                dispatched_at = NULL, last_error_code = NULL, updated_at = $5 \
         WHERE delivery_id = $1 AND tenant_id = $2",
    )
    .bind(delivery_id.as_uuid())
    .bind(tenant_id.as_uuid())
    .bind(encoded.id().as_uuid())
    .bind(encoded.bytes())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if outbox.rows_affected() != 1 {
        return Err(NotificationError::InvalidState);
    }
    let delivery = sqlx::query(
        "UPDATE deliveries SET status = 'pending_dispatch', send_lease_token = NULL, \
                send_lease_expires_at = NULL, enqueued_at = NULL, updated_at = $3 \
         WHERE id = $1 AND tenant_id = $2 AND status IN ('sending', 'retryable')",
    )
    .bind(delivery_id.as_uuid())
    .bind(tenant_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if delivery.rows_affected() != 1 {
        return Err(NotificationError::InvalidState);
    }
    Ok(())
}

fn delivery_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<(DeliveryId, TenantId, NotificationEmailJob), NotificationError> {
    let delivery_id = DeliveryId::from_uuid(
        row.try_get("id")
            .map_err(|_| NotificationError::InvalidState)?,
    )?;
    let tenant_id = TenantId::from_uuid(
        row.try_get("tenant_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let recipient_id = SubjectId::from_uuid(
        row.try_get("recipient_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let template_base: String = row
        .try_get("template_name")
        .map_err(|_| NotificationError::InvalidState)?;
    let template_version: i32 = row
        .try_get("template_version")
        .map_err(|_| NotificationError::InvalidState)?;
    let template = versioned_template_name(&template_base, template_version)?;
    let locale = Locale::try_from(
        row.try_get::<String, _>("locale")
            .map_err(|_| NotificationError::InvalidState)?,
    )?;
    let job = NotificationEmailJob::new(
        delivery_id,
        template,
        u32::try_from(template_version).map_err(|_| NotificationError::InvalidState)?,
        recipient_id,
        locale,
    );
    Ok((delivery_id, tenant_id, job))
}

const fn provider_event_outcome_label(outcome: ProviderEventOutcome) -> &'static str {
    match outcome {
        ProviderEventOutcome::Applied(_) => "applied",
        ProviderEventOutcome::Duplicate(_) => "duplicate",
        ProviderEventOutcome::Ignored(_) => "ignored",
    }
}

const fn provider_event_outcome_status(outcome: ProviderEventOutcome) -> DeliveryStatus {
    match outcome {
        ProviderEventOutcome::Applied(status)
        | ProviderEventOutcome::Duplicate(status)
        | ProviderEventOutcome::Ignored(status) => status,
    }
}

async fn prepare_schedule_plan(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    channel: NotificationChannel,
    now: OffsetDateTime,
) -> Result<SchedulePlan, NotificationError> {
    match request.delivery_mode() {
        DeliveryMode::Immediate => Ok(SchedulePlan {
            digest_bucket_id: None,
            dedupe_bucket_started_at: OffsetDateTime::UNIX_EPOCH,
            initial_status: DeliveryStatus::PendingDispatch,
            available_at: now,
        }),
        DeliveryMode::Digest(spec) => {
            let start_seconds = now.unix_timestamp()
                - now
                    .unix_timestamp()
                    .rem_euclid(i64::from(spec.window_seconds()));
            let bucket_started_at = OffsetDateTime::from_unix_timestamp(start_seconds)
                .map_err(|_| NotificationError::InvalidState)?;
            let bucket_ends_at =
                bucket_started_at + time::Duration::seconds(i64::from(spec.window_seconds()));
            let bucket_id = ensure_digest_bucket(
                transaction,
                request,
                channel,
                spec.key().as_str(),
                spec.window_seconds(),
                bucket_started_at,
                bucket_ends_at,
            )
            .await?;
            Ok(SchedulePlan {
                digest_bucket_id: Some(bucket_id),
                dedupe_bucket_started_at: bucket_started_at,
                initial_status: DeliveryStatus::DigestPending,
                available_at: bucket_ends_at,
            })
        }
    }
}

async fn insert_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    channel: NotificationChannel,
    plan: &SchedulePlan,
    now: OffsetDateTime,
) -> Result<(DeliveryId, Option<sqlx::postgres::PgRow>), NotificationError> {
    let delivery_id = DeliveryId::new();
    let effect_key = effect_key(delivery_id)?;
    let client_message_id = format!("<{delivery_id}@omnius.invalid>");
    let context = serde_json::to_value(request.email().context())
        .map_err(|_| NotificationError::InvalidState)?;
    let inserted = sqlx::query(
        "INSERT INTO deliveries ( \
            id, tenant_id, recipient_id, event_name, channel, classification, \
            preference_category, locale, time_zone, template_name, template_version, \
            recipient_email, recipient_display_name, from_email, from_display_name, subject, \
            template_context, dedupe_key, dedupe_bucket_started_at, digest_bucket_id, \
            effect_key, client_message_id, status, correlation_id, causation_id, \
            created_at, updated_at \
         ) VALUES ( \
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
            $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $26 \
         ) ON CONFLICT (tenant_id, channel, dedupe_key, dedupe_bucket_started_at) \
         DO NOTHING \
         RETURNING id, tenant_id, recipient_id, channel, status, attempt_count, \
                   template_version, created_at, updated_at",
    )
    .bind(delivery_id.as_uuid())
    .bind(request.tenant_id().as_uuid())
    .bind(request.recipient_id().as_uuid())
    .bind(request.event().as_str())
    .bind(channel.as_str())
    .bind(request.classification().as_str())
    .bind(
        request
            .classification()
            .preference_category()
            .map(PreferenceCategory::as_str),
    )
    .bind(request.locale().as_str())
    .bind(request.time_zone().as_str())
    .bind(request.email().template().base().as_str())
    .bind(
        i32::try_from(request.email().template().version())
            .map_err(|_| NotificationError::InvalidRequest)?,
    )
    .bind(request.email().recipient().address().as_str())
    .bind(
        request
            .email()
            .recipient()
            .display_name()
            .map(DisplayName::as_str),
    )
    .bind(request.email().from().address().as_str())
    .bind(
        request
            .email()
            .from()
            .display_name()
            .map(DisplayName::as_str),
    )
    .bind(request.email().subject().as_str())
    .bind(sqlx::types::Json(&context))
    .bind(request.dedupe_key().as_str())
    .bind(plan.dedupe_bucket_started_at)
    .bind(plan.digest_bucket_id)
    .bind(effect_key.as_str())
    .bind(client_message_id)
    .bind(plan.initial_status.as_str())
    .bind(request.correlation_id().as_uuid())
    .bind(request.causation_id().map(CausationId::as_uuid))
    .bind(now)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    Ok((delivery_id, inserted))
}

async fn load_duplicate_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    channel: NotificationChannel,
    plan: &SchedulePlan,
) -> Result<SchedulePersistence, NotificationError> {
    let existing = sqlx::query(
        "SELECT d.*, b.digest_key AS existing_digest_key, \
                b.window_seconds AS existing_digest_window_seconds \
         FROM deliveries d \
         LEFT JOIN notification_digest_buckets b ON b.id = d.digest_bucket_id \
         WHERE d.tenant_id = $1 AND d.channel = $2 AND d.dedupe_key = $3 \
           AND d.dedupe_bucket_started_at = $4",
    )
    .bind(request.tenant_id().as_uuid())
    .bind(channel.as_str())
    .bind(request.dedupe_key().as_str())
    .bind(plan.dedupe_bucket_started_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if !duplicate_matches(&existing, request)? {
        return Err(NotificationError::ConstraintViolation);
    }
    let delivery_id = existing
        .try_get::<Uuid, _>("id")
        .map_err(|_| NotificationError::InvalidState)?;
    let has_pending_outbox: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM notification_job_outbox \
         WHERE delivery_id = $1 AND dispatched_at IS NULL)",
    )
    .bind(delivery_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    Ok(SchedulePersistence {
        record: delivery_record(&existing)?,
        inserted: false,
        has_pending_outbox,
    })
}

async fn finalize_new_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    channel: NotificationChannel,
    delivery_id: DeliveryId,
    plan: &SchedulePlan,
    now: OffsetDateTime,
) -> Result<(), NotificationError> {
    if let Some(bucket_id) = plan.digest_bucket_id {
        add_digest_member(transaction, request, delivery_id, bucket_id).await
    } else {
        insert_job_outbox(
            transaction,
            request,
            delivery_id,
            channel,
            plan.available_at,
            now,
        )
        .await
    }
}

async fn add_digest_member(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    delivery_id: DeliveryId,
    bucket_id: Uuid,
) -> Result<(), NotificationError> {
    let context_bytes = i64::try_from(request.email().context().serialized_bytes())
        .map_err(|_| NotificationError::DigestFull)?;
    let existing_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(template_context::text)), 0)::bigint \
         FROM deliveries WHERE digest_bucket_id = $1 AND id <> $2",
    )
    .bind(bucket_id)
    .bind(delivery_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if existing_bytes.saturating_add(context_bytes) > MAX_DIGEST_CONTEXT_BYTES {
        return Err(NotificationError::DigestFull);
    }
    let leader: Option<Uuid> = sqlx::query_scalar(
        "UPDATE notification_digest_buckets \
         SET member_count = member_count + 1, \
             leader_delivery_id = COALESCE(leader_delivery_id, $2) \
         WHERE id = $1 AND released_at IS NULL AND member_count < 256 \
         RETURNING leader_delivery_id",
    )
    .bind(bucket_id)
    .bind(delivery_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?
    .flatten();
    if leader.is_none() {
        return Err(NotificationError::DigestFull);
    }
    Ok(())
}

async fn release_digest_bucket(
    transaction: &mut Transaction<'_, Postgres>,
    row: &sqlx::postgres::PgRow,
    now: OffsetDateTime,
) -> Result<(), NotificationError> {
    let bucket_id: Uuid = row
        .try_get("bucket_id")
        .map_err(|_| NotificationError::InvalidState)?;
    validate_digest_aggregate(transaction, bucket_id).await?;
    let (delivery_id, tenant_id, job) = digest_job_from_row(row)?;
    let envelope = build_envelope(
        job,
        tenant_id,
        row.try_get("correlation_id")
            .map_err(|_| NotificationError::InvalidState)?,
        row.try_get("causation_id")
            .map_err(|_| NotificationError::InvalidState)?,
        now,
    )?;
    let encoded = envelope
        .encode()
        .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    persist_digest_release(
        transaction,
        bucket_id,
        delivery_id,
        tenant_id,
        &encoded,
        now,
    )
    .await
}

async fn validate_digest_aggregate(
    transaction: &mut Transaction<'_, Postgres>,
    bucket_id: Uuid,
) -> Result<(), NotificationError> {
    // Member rows and their contexts are immutable. Validate the exact deterministic aggregate
    // before any member becomes final.
    let assembled = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT jsonb_build_object( \
            'items', COALESCE(jsonb_agg(template_context ORDER BY created_at, id), '[]'::jsonb), \
            'count', count(*) \
         ) FROM deliveries WHERE digest_bucket_id = $1",
    )
    .bind(bucket_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?
    .0;
    TemplateContext::new(assembled)
        .map(|_| ())
        .map_err(|_| NotificationError::DigestFull)
}

fn digest_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<(DeliveryId, TenantId, NotificationEmailJob), NotificationError> {
    let delivery_id = DeliveryId::from_uuid(
        row.try_get("leader_delivery_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )?;
    let tenant_id = TenantId::from_uuid(
        row.try_get("tenant_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let recipient_id = SubjectId::from_uuid(
        row.try_get("recipient_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let template_base: String = row
        .try_get("template_name")
        .map_err(|_| NotificationError::InvalidState)?;
    let template_version: i32 = row
        .try_get("template_version")
        .map_err(|_| NotificationError::InvalidState)?;
    let template = versioned_template_name(&template_base, template_version)?;
    let locale = Locale::try_from(
        row.try_get::<String, _>("locale")
            .map_err(|_| NotificationError::InvalidState)?,
    )?;
    let job = NotificationEmailJob::new(
        delivery_id,
        template,
        u32::try_from(template_version).map_err(|_| NotificationError::InvalidState)?,
        recipient_id,
        locale,
    );
    Ok((delivery_id, tenant_id, job))
}

async fn persist_digest_release(
    transaction: &mut Transaction<'_, Postgres>,
    bucket_id: Uuid,
    delivery_id: DeliveryId,
    tenant_id: TenantId,
    encoded: &EncodedJobEnvelope,
    now: OffsetDateTime,
) -> Result<(), NotificationError> {
    sqlx::query(
        "INSERT INTO notification_job_outbox \
         (delivery_id, tenant_id, job_id, envelope, available_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $5, $5) ON CONFLICT (delivery_id) DO NOTHING",
    )
    .bind(delivery_id.as_uuid())
    .bind(tenant_id.as_uuid())
    .bind(encoded.id().as_uuid())
    .bind(encoded.bytes())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    sqlx::query(
        "UPDATE deliveries SET status = 'coalesced', final_at = $3, updated_at = $3 \
         WHERE digest_bucket_id = $1 AND id <> $2 AND status = 'digest_pending'",
    )
    .bind(bucket_id)
    .bind(delivery_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    sqlx::query(
        "UPDATE deliveries SET status = 'pending_dispatch', updated_at = $2 \
         WHERE id = $1 AND status = 'digest_pending'",
    )
    .bind(delivery_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    sqlx::query("UPDATE notification_digest_buckets SET released_at = $2 WHERE id = $1")
        .bind(bucket_id)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
    Ok(())
}

async fn optional_preference_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    row: &sqlx::postgres::PgRow,
    tenant_id: TenantId,
    job: &NotificationEmailJob,
    now: OffsetDateTime,
) -> Result<Option<ClaimOutcome>, NotificationError> {
    if row
        .try_get::<String, _>("classification")
        .map_err(|_| NotificationError::InvalidState)?
        != "optional"
    {
        return Ok(None);
    }
    let category: String = row
        .try_get("preference_category")
        .map_err(|_| NotificationError::InvalidState)?;
    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT enabled FROM notification_preferences \
         WHERE recipient_id = $1 AND category = $2 AND channel = 'email' \
           AND (tenant_id = $3 OR tenant_id IS NULL) \
         ORDER BY (tenant_id IS NOT NULL) DESC LIMIT 1",
    )
    .bind(job.recipient_id().as_uuid())
    .bind(category)
    .bind(tenant_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if enabled != Some(false) {
        return Ok(None);
    }
    sqlx::query(
        "UPDATE deliveries SET status = 'suppressed', final_at = $3, updated_at = $3, \
            send_lease_token = NULL, send_lease_expires_at = NULL \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id.as_uuid())
    .bind(job.delivery_id().as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    Ok(Some(ClaimOutcome::Terminal(DeliveryStatus::Suppressed)))
}

fn unavailable_claim_outcome(
    row: &sqlx::postgres::PgRow,
    status: DeliveryStatus,
    now: OffsetDateTime,
) -> Result<Option<ClaimOutcome>, NotificationError> {
    if status == DeliveryStatus::Sending {
        let expires: OffsetDateTime = row
            .try_get("send_lease_expires_at")
            .map_err(|_| NotificationError::InvalidState)?;
        return Ok((expires > now).then_some(ClaimOutcome::Busy));
    }
    if matches!(status, DeliveryStatus::Queued | DeliveryStatus::Retryable) {
        Ok(None)
    } else {
        Err(NotificationError::InvalidState)
    }
}

async fn claim_email_effect(
    transaction: &mut Transaction<'_, Postgres>,
    row: &sqlx::postgres::PgRow,
    tenant_id: TenantId,
    job: &NotificationEmailJob,
    context: &DeliveryContext,
    now: OffsetDateTime,
) -> Result<ClaimedEmailEffect, NotificationError> {
    let lease_token = Uuid::now_v7();
    let result = sqlx::query(
        "UPDATE deliveries SET status = 'sending', \
                attempt_count = CASE WHEN attempt_count < 2147483647 \
                    THEN attempt_count + 1 ELSE attempt_count END, \
                send_lease_token = $3, send_lease_expires_at = $4, last_failure_code = NULL, \
                updated_at = $5 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id.as_uuid())
    .bind(job.delivery_id().as_uuid())
    .bind(lease_token)
    .bind(context.deadline())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    if result.rows_affected() != 1 {
        return Err(NotificationError::InvalidState);
    }
    let request = build_email_request(transaction, row).await?;
    let client_message_id = ClientMessageId::try_from(
        row.try_get::<String, _>("client_message_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    Ok(ClaimedEmailEffect {
        request,
        fence: DeliveryFence {
            tenant_id,
            delivery_id: job.delivery_id(),
            lease_token,
        },
        client_message_id,
    })
}

impl fmt::Debug for PostgresNotificationRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresNotificationRepository")
            .finish_non_exhaustive()
    }
}

async fn ensure_digest_bucket(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    channel: NotificationChannel,
    digest_key: &str,
    window_seconds: u32,
    bucket_started_at: OffsetDateTime,
    bucket_ends_at: OffsetDateTime,
) -> Result<Uuid, NotificationError> {
    let category = request
        .classification()
        .preference_category()
        .ok_or(NotificationError::InvalidRequest)?;
    let candidate = Uuid::now_v7();
    let fingerprint = request.presentation_fingerprint();
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO notification_digest_buckets (id, tenant_id, recipient_id, category, channel, \
             digest_key, window_seconds, bucket_started_at, bucket_ends_at, presentation_fingerprint) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
         ON CONFLICT (tenant_id, recipient_id, category, channel, digest_key, bucket_started_at) \
         DO NOTHING RETURNING id",
    )
    .bind(candidate).bind(request.tenant_id().as_uuid()).bind(request.recipient_id().as_uuid())
    .bind(category.as_str()).bind(channel.as_str()).bind(digest_key)
    .bind(i32::try_from(window_seconds).map_err(|_| NotificationError::InvalidRequest)?)
    .bind(bucket_started_at).bind(bucket_ends_at).bind(fingerprint.as_slice())
    .fetch_optional(&mut **transaction).await.map_err(|error| map_sqlx(&error))?;
    if let Some(id) = inserted {
        return Ok(id);
    }
    let row = sqlx::query(
        "SELECT id, presentation_fingerprint, member_count, released_at \
         FROM notification_digest_buckets WHERE tenant_id=$1 AND recipient_id=$2 AND category=$3 \
           AND channel=$4 AND digest_key=$5 AND bucket_started_at=$6 FOR UPDATE",
    )
    .bind(request.tenant_id().as_uuid())
    .bind(request.recipient_id().as_uuid())
    .bind(category.as_str())
    .bind(channel.as_str())
    .bind(digest_key)
    .bind(bucket_started_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    let stored: Vec<u8> = row
        .try_get("presentation_fingerprint")
        .map_err(|_| NotificationError::InvalidState)?;
    if stored.as_slice() != fingerprint
        || row
            .try_get::<Option<OffsetDateTime>, _>("released_at")
            .map_err(|_| NotificationError::InvalidState)?
            .is_some()
    {
        return Err(NotificationError::DigestConflict);
    }
    if row
        .try_get::<i32, _>("member_count")
        .map_err(|_| NotificationError::InvalidState)?
        >= 256
    {
        return Err(NotificationError::DigestFull);
    }
    row.try_get("id")
        .map_err(|_| NotificationError::InvalidState)
}

async fn insert_job_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NotificationRequest,
    delivery_id: DeliveryId,
    _channel: NotificationChannel,
    available_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), NotificationError> {
    let job = NotificationEmailJob::new(
        delivery_id,
        request.email().template().name().clone(),
        request.email().template().version(),
        request.recipient_id(),
        request.locale().clone(),
    );
    let envelope = build_envelope(
        job,
        request.tenant_id(),
        request.correlation_id().as_uuid(),
        request.causation_id().map(CausationId::as_uuid),
        available_at,
    )?;
    let encoded = envelope
        .encode()
        .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    sqlx::query(
        "INSERT INTO notification_job_outbox (delivery_id, tenant_id, job_id, envelope, available_at, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$6)",
    )
    .bind(delivery_id.as_uuid()).bind(request.tenant_id().as_uuid()).bind(encoded.id().as_uuid())
    .bind(encoded.bytes()).bind(available_at).bind(now)
    .execute(&mut **transaction).await.map_err(|error| map_sqlx(&error))?;
    Ok(())
}

fn pending_outbox(
    row: &sqlx::postgres::PgRow,
    lease_token: Uuid,
) -> Result<PendingOutbox, NotificationError> {
    let delivery_id = DeliveryId::from_uuid(
        row.try_get("delivery_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )?;
    let tenant_id = TenantId::from_uuid(
        row.try_get("tenant_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let job_id = JobId::from_uuid(
        row.try_get("job_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let bytes: Vec<u8> = row
        .try_get("envelope")
        .map_err(|_| NotificationError::InvalidState)?;
    let queue =
        QueueName::try_from("notifications").map_err(|_| NotificationError::InvalidJobEnvelope)?;
    let envelope = EncodedJobEnvelope::restore(&bytes, queue)
        .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    let typed = envelope
        .decode::<NotificationEmailJob>()
        .map_err(|_| NotificationError::InvalidJobEnvelope)?;
    if envelope.id() != job_id || typed.payload().delivery_id() != delivery_id {
        return Err(NotificationError::InvalidState);
    }
    Ok(PendingOutbox {
        delivery_id,
        tenant_id,
        job_id,
        lease_token,
        envelope,
    })
}

fn validate_job_identity(
    row: &sqlx::postgres::PgRow,
    job: &NotificationEmailJob,
    context: &DeliveryContext,
) -> Result<(), NotificationError> {
    let template: String = row
        .try_get("template_name")
        .map_err(|_| NotificationError::InvalidState)?;
    let version: i32 = row
        .try_get("template_version")
        .map_err(|_| NotificationError::InvalidState)?;
    let recipient: Uuid = row
        .try_get("recipient_id")
        .map_err(|_| NotificationError::InvalidState)?;
    let locale: String = row
        .try_get("locale")
        .map_err(|_| NotificationError::InvalidState)?;
    let effect: String = row
        .try_get("effect_key")
        .map_err(|_| NotificationError::InvalidState)?;
    let last_job_id = row
        .try_get::<Option<Uuid>, _>("last_job_id")
        .map_err(|_| NotificationError::InvalidState)?
        .ok_or(NotificationError::InvalidState)?;
    let versioned_template = versioned_template_name(&template, version)?;
    if versioned_template.as_str() != job.template().as_str()
        || u32::try_from(version).ok() != Some(job.template_version())
        || recipient != job.recipient_id().as_uuid()
        || locale != job.locale().as_str()
        || last_job_id != context.effect_identity().job_id().as_uuid()
        || context
            .effect_identity()
            .idempotency_key()
            .map(IdempotencyKey::as_str)
            != Some(effect.as_str())
    {
        return Err(NotificationError::InvalidState);
    }
    Ok(())
}

async fn build_email_request(
    transaction: &mut Transaction<'_, Postgres>,
    row: &sqlx::postgres::PgRow,
) -> Result<SendEmailRequest, NotificationError> {
    let recipient = mailbox(row, "recipient_email", "recipient_display_name")?;
    let from = mailbox(row, "from_email", "from_display_name")?;
    let recipients = RecipientSet::new(vec![recipient], Vec::new(), Vec::new())
        .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    let subject = EmailSubject::try_from(
        row.try_get::<String, _>("subject")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    let template_base: String = row
        .try_get("template_name")
        .map_err(|_| NotificationError::InvalidState)?;
    let template_version: i32 = row
        .try_get("template_version")
        .map_err(|_| NotificationError::InvalidState)?;
    let template = versioned_template_name(&template_base, template_version)
        .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    let context_value = if let Some(bucket_id) = row
        .try_get::<Option<Uuid>, _>("digest_bucket_id")
        .map_err(|_| NotificationError::InvalidState)?
    {
        sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
            "SELECT jsonb_build_object('items', COALESCE(jsonb_agg(template_context ORDER BY created_at, id), '[]'::jsonb), 'count', count(*)) \
             FROM deliveries WHERE digest_bucket_id = $1",
        ).bind(bucket_id).fetch_one(&mut **transaction).await.map_err(|error| map_sqlx(&error))?.0
    } else {
        row.try_get::<sqlx::types::Json<Value>, _>("template_context")
            .map_err(|_| NotificationError::InvalidState)?
            .0
    };
    let context = TemplateContext::new(context_value)
        .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    let idempotency = omnius_jobs_core::IdempotencyKey::try_from(
        row.try_get::<String, _>("effect_key")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidState)?;
    let client = ClientMessageId::try_from(
        row.try_get::<String, _>("client_message_id")
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    Ok(SendEmailRequest::new(
        idempotency,
        client,
        from,
        recipients,
        subject,
        template,
        context,
    ))
}

fn mailbox(
    row: &sqlx::postgres::PgRow,
    address_column: &str,
    display_column: &str,
) -> Result<MailboxAddress, NotificationError> {
    let address = EmailAddress::try_from(
        row.try_get::<String, _>(address_column)
            .map_err(|_| NotificationError::InvalidState)?,
    )
    .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    let display = row
        .try_get::<Option<String>, _>(display_column)
        .map_err(|_| NotificationError::InvalidState)?
        .map(DisplayName::try_from)
        .transpose()
        .map_err(|_| NotificationError::InvalidEmailPresentation)?;
    Ok(MailboxAddress::new(address, display))
}

fn delivery_record(row: &sqlx::postgres::PgRow) -> Result<DeliveryRecord, NotificationError> {
    let channel = match row
        .try_get::<String, _>("channel")
        .map_err(|_| NotificationError::InvalidState)?
        .as_str()
    {
        "email" => NotificationChannel::Email,
        _ => return Err(NotificationError::InvalidState),
    };
    let attempts: i32 = row
        .try_get("attempt_count")
        .map_err(|_| NotificationError::InvalidState)?;
    let version: i32 = row
        .try_get("template_version")
        .map_err(|_| NotificationError::InvalidState)?;
    Ok(DeliveryRecord {
        id: DeliveryId::from_uuid(
            row.try_get("id")
                .map_err(|_| NotificationError::InvalidState)?,
        )?,
        tenant_id: TenantId::from_uuid(
            row.try_get("tenant_id")
                .map_err(|_| NotificationError::InvalidState)?,
        )
        .map_err(|_| NotificationError::InvalidState)?,
        recipient_id: SubjectId::from_uuid(
            row.try_get("recipient_id")
                .map_err(|_| NotificationError::InvalidState)?,
        )
        .map_err(|_| NotificationError::InvalidState)?,
        channel,
        status: row
            .try_get::<String, _>("status")
            .map_err(|_| NotificationError::InvalidState)?
            .parse()?,
        attempt_count: u16::try_from(attempts).unwrap_or(u16::MAX),
        template_version: u32::try_from(version).map_err(|_| NotificationError::InvalidState)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| NotificationError::InvalidState)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| NotificationError::InvalidState)?,
    })
}

fn duplicate_matches(
    row: &sqlx::postgres::PgRow,
    request: &NotificationRequest,
) -> Result<bool, NotificationError> {
    let stored_context = row
        .try_get::<sqlx::types::Json<Value>, _>("template_context")
        .map_err(|_| NotificationError::InvalidState)?
        .0;
    let requested_context = serde_json::to_value(request.email().context())
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_version: i32 = row
        .try_get("template_version")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_category: Option<String> = row
        .try_get("preference_category")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_recipient_name: Option<String> = row
        .try_get("recipient_display_name")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_from_name: Option<String> = row
        .try_get("from_display_name")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_digest_key: Option<String> = row
        .try_get("existing_digest_key")
        .map_err(|_| NotificationError::InvalidState)?;
    let stored_digest_window: Option<i32> = row
        .try_get("existing_digest_window_seconds")
        .map_err(|_| NotificationError::InvalidState)?;
    let mode_matches = match request.delivery_mode() {
        DeliveryMode::Immediate => stored_digest_key.is_none() && stored_digest_window.is_none(),
        DeliveryMode::Digest(spec) => {
            stored_digest_key.as_deref() == Some(spec.key().as_str())
                && stored_digest_window == i32::try_from(spec.window_seconds()).ok()
        }
    };
    Ok(row
        .try_get::<Uuid, _>("recipient_id")
        .map_err(|_| NotificationError::InvalidState)?
        == request.recipient_id().as_uuid()
        && row
            .try_get::<String, _>("event_name")
            .map_err(|_| NotificationError::InvalidState)?
            == request.event().as_str()
        && row
            .try_get::<String, _>("classification")
            .map_err(|_| NotificationError::InvalidState)?
            == request.classification().as_str()
        && stored_category.as_deref()
            == request
                .classification()
                .preference_category()
                .map(PreferenceCategory::as_str)
        && row
            .try_get::<String, _>("locale")
            .map_err(|_| NotificationError::InvalidState)?
            == request.locale().as_str()
        && row
            .try_get::<String, _>("time_zone")
            .map_err(|_| NotificationError::InvalidState)?
            == request.time_zone().as_str()
        && row
            .try_get::<String, _>("template_name")
            .map_err(|_| NotificationError::InvalidState)?
            == request.email().template().base().as_str()
        && u32::try_from(stored_version).ok() == Some(request.email().template().version())
        && row
            .try_get::<String, _>("recipient_email")
            .map_err(|_| NotificationError::InvalidState)?
            == request.email().recipient().address().as_str()
        && stored_recipient_name.as_deref()
            == request
                .email()
                .recipient()
                .display_name()
                .map(DisplayName::as_str)
        && row
            .try_get::<String, _>("from_email")
            .map_err(|_| NotificationError::InvalidState)?
            == request.email().from().address().as_str()
        && stored_from_name.as_deref()
            == request
                .email()
                .from()
                .display_name()
                .map(DisplayName::as_str)
        && row
            .try_get::<String, _>("subject")
            .map_err(|_| NotificationError::InvalidState)?
            == request.email().subject().as_str()
        && stored_context == requested_context
        && mode_matches)
}

fn versioned_template_name(base: &str, version: i32) -> Result<TemplateName, NotificationError> {
    if version < 1 {
        return Err(NotificationError::InvalidState);
    }
    TemplateName::try_from(format!("{base}-v{version}"))
        .map_err(|_| NotificationError::InvalidState)
}

fn postgres_interval_micros(duration: Duration) -> Result<i64, NotificationError> {
    let rounded = duration.as_nanos().saturating_add(999) / 1_000;
    i64::try_from(rounded).map_err(|_| NotificationError::InvalidRequest)
}
