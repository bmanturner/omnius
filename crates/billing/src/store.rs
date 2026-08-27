use std::{fmt, time::Duration};

use metrics::counter;
use omnius_audit::{
    AuditActor, AuditAppendOutcome, AuditEvent, AuditEventType, AuditOutcome, AuditResourceId,
    AuditScope, PostgresAuditSink,
};
use omnius_auth_core::{Principal, PrincipalKind, TenantId};
use omnius_authz_basic::{Action, ResourceKind};
use omnius_jobs_core::{
    Destination, DomainEvent, EventEnvelope, EventEnvelopeOptions, EventLimits, Source, Subject,
    TenantId as JobTenantId,
};
use omnius_outbox::PostgresOutbox;
use omnius_postgres::{PostgresError, PostgresPool};
use omnius_tenancy::TenantContext;
use omnius_webhooks_inbound::ReceiptId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{Connection as _, PgConnection, Row as _};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    BillingConfig, BillingStanding, BillingValueError, EffectiveEntitlement, EntitlementKey,
    EntitlementValue, MeterKey, NewUsageRecord, PlanDefinition, ProviderEvent, ProviderId,
    ProviderPriceMapping, ProviderRevision, ProviderSnapshot, ProviderUsageRequest,
    ReconciliationTaskId, RepairIdempotencyKey, UsageAcknowledgement, UsageIdempotencyKey,
    UsageRecordId,
};

const FAILURE_SNAPSHOT_CONFLICT: &str = "snapshot_conflict";
const OUTBOX_DESTINATION: &str = "billing.entitlements";
const MAX_USAGE_FUTURE_SKEW: time::Duration = time::Duration::minutes(5);
const MAX_EFFECTIVE_ENTITLEMENTS: u64 = 512;

struct SubscriptionAccess {
    state: &'static str,
    grace_until: Option<OffsetDateTime>,
    dunning_started_at: Option<OffsetDateTime>,
    dunning_attempt_count: Option<i32>,
    dunning_next_attempt_at: Option<OffsetDateTime>,
}

struct AuditRecord {
    actor: AuditActor,
    scope: AuditScope,
    event_type: &'static str,
    action: &'static str,
    resource_kind: &'static str,
    resource_id: Option<String>,
    outcome: AuditOutcome,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EventSequenceDisposition {
    Current,
    OutOfOrder,
    Conflict,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SnapshotRevisionDisposition {
    Publish,
    Stale,
    Duplicate,
    Conflict,
}

/// Durable enqueue result for one provider event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventEnqueueOutcome {
    /// A new monotonic event and reconciliation task were committed.
    Enqueued(ReconciliationTaskId),
    /// The exact previously committed event was replayed.
    Duplicate(ReconciliationTaskId),
    /// A new event arrived at or behind the committed provider sequence fence.
    OutOfOrder,
    /// A committed event identity or sequence was reused with different facts.
    Conflict,
}

/// Durable enqueue result for an operator-requested repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairEnqueueOutcome {
    /// A new repair task was committed and audited.
    Enqueued(ReconciliationTaskId),
    /// The same tenant/provider/idempotency request already exists.
    Duplicate(ReconciliationTaskId),
}

/// Durable usage idempotency classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageRecordOutcome {
    /// A new pending usage fact was committed and audited.
    Recorded(UsageRecordId),
    /// The exact usage fact was already committed.
    Duplicate(UsageRecordId),
    /// The tenant/meter/idempotency identity was reused with different facts.
    Conflict,
}

/// Result of a provider-idempotent usage acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageCompletionOutcome {
    /// Pending local usage became provider-accepted.
    Accepted,
    /// The identical acknowledgement was already recorded.
    Duplicate,
    /// A different provider result attempted to reuse the local record.
    Conflict,
}

/// Durable terminal state of one tenant-scoped usage record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageRecordState {
    /// Provider acknowledgement is durably recorded.
    Accepted,
    /// Provider submission was durably rejected and must not be retried.
    Rejected,
    /// Work remains pending or leased.
    Pending,
}

/// Atomic result of publishing an authoritative provider snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotApplyOutcome {
    /// Mirrors and effective entitlements moved to a newer provider revision.
    Applied {
        /// Number of effective entitlement rows after publication.
        entitlement_count: u64,
    },
    /// The same revision and fingerprint were already published.
    Duplicate,
    /// A newer snapshot was already published; no mirrors changed.
    Stale,
    /// The same revision carried different content and was dead-lettered.
    Conflict,
}

/// One live database-clock reconciliation lease.
pub struct ClaimedReconciliation {
    id: ReconciliationTaskId,
    tenant_id: TenantId,
    provider: ProviderId,
    lease_token: Uuid,
    lease_expires_at: OffsetDateTime,
    attempt_count: u16,
}

impl ClaimedReconciliation {
    /// Returns the durable task identity.
    #[must_use]
    pub const fn id(&self) -> ReconciliationTaskId {
        self.id
    }

    /// Returns the canonical tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the exact provider adapter identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the database-clock lease deadline.
    #[must_use]
    pub const fn lease_expires_at(&self) -> OffsetDateTime {
        self.lease_expires_at
    }

    /// Returns the attempt count including this lease.
    #[must_use]
    pub const fn attempt_count(&self) -> u16 {
        self.attempt_count
    }
}

impl fmt::Debug for ClaimedReconciliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedReconciliation")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("provider", &self.provider)
            .field("lease_token", &"[REDACTED]")
            .field("lease_expires_at", &self.lease_expires_at)
            .field("attempt_count", &self.attempt_count)
            .finish()
    }
}

/// One live database-clock lease for a durable provider-idempotent usage submission.
pub struct ClaimedUsage {
    request: ProviderUsageRequest,
    provider: ProviderId,
    lease_token: Uuid,
    lease_expires_at: OffsetDateTime,
    attempt_count: u16,
}

impl ClaimedUsage {
    /// Returns the reconstructed bounded provider submission.
    #[must_use]
    pub const fn request(&self) -> &ProviderUsageRequest {
        &self.request
    }

    /// Returns the exact provider adapter identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the database-clock lease deadline.
    #[must_use]
    pub const fn lease_expires_at(&self) -> OffsetDateTime {
        self.lease_expires_at
    }

    /// Returns the attempt count including this lease.
    #[must_use]
    pub const fn attempt_count(&self) -> u16 {
        self.attempt_count
    }
}

impl fmt::Debug for ClaimedUsage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedUsage")
            .field("record_id", &self.request.record_id())
            .field("provider", &self.provider)
            .field("lease_token", &"[REDACTED]")
            .field("lease_expires_at", &self.lease_expires_at)
            .field("attempt_count", &self.attempt_count)
            .finish_non_exhaustive()
    }
}

/// Typed outbox event emitted in the same transaction as entitlement publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntitlementsReconciled {
    /// Canonical tenant whose local grants changed.
    pub tenant_id: TenantId,
    /// Exact provider adapter whose API snapshot was published.
    pub provider: ProviderId,
    /// Monotonic provider API snapshot revision.
    pub provider_revision: i64,
    /// Number of effective local entitlement rows after publication.
    pub entitlement_count: u64,
}

impl DomainEvent for EntitlementsReconciled {
    const NAME: &'static str = "billing.entitlements_reconciled.v1";
    const VERSION: u16 = 1;
}

/// PostgreSQL-authoritative billing mirrors, fences, leases, usage, audit, and outbox intents.
#[derive(Clone)]
pub struct PostgresBillingStore {
    pool: PostgresPool,
    audit: PostgresAuditSink,
    outbox: PostgresOutbox,
    config: BillingConfig,
}

impl PostgresBillingStore {
    /// Creates an enabled store after validating all local safety bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BillingStoreError::InvalidConfiguration`] when billing is disabled or invalid.
    pub fn new(
        pool: PostgresPool,
        audit: PostgresAuditSink,
        outbox: PostgresOutbox,
        config: BillingConfig,
    ) -> Result<Self, BillingStoreError> {
        config
            .validate()
            .map_err(|_| BillingStoreError::InvalidConfiguration)?;
        if !config.enabled || !audit.config().enabled {
            return Err(BillingStoreError::InvalidConfiguration);
        }
        Ok(Self {
            pool,
            audit,
            outbox,
            config,
        })
    }

    /// Returns the validated execution policy.
    #[must_use]
    pub const fn config(&self) -> BillingConfig {
        self.config
    }

    /// Replaces one application plan and its grants atomically with an audit record.
    ///
    /// Entitlement value kinds are global invariants: a key cannot be boolean in one plan and a
    /// limit in another.
    ///
    /// # Errors
    ///
    /// Returns a safe persistence, type-conflict, or audit error.
    pub async fn put_plan(&self, plan: &PlanDefinition) -> Result<(), BillingStoreError> {
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        sqlx::query(
            "INSERT INTO billing_plans (plan_key, enabled, created_at, updated_at) \
             VALUES ($1, $2, clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (plan_key) DO UPDATE SET \
                enabled = EXCLUDED.enabled, updated_at = clock_timestamp()",
        )
        .bind(plan.key().as_str())
        .bind(plan.enabled())
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;

        for grant in plan.entitlements() {
            sqlx::query(
                "INSERT INTO billing_entitlement_definitions \
                    (entitlement_key, value_kind, created_at) \
                 VALUES ($1, $2, clock_timestamp()) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(grant.key().as_str())
            .bind(grant.value().kind())
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let existing_kind: String = sqlx::query_scalar(
                "SELECT value_kind FROM billing_entitlement_definitions \
                 WHERE entitlement_key = $1 FOR UPDATE",
            )
            .bind(grant.key().as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            if existing_kind != grant.value().kind() {
                return Err(BillingStoreError::Conflict);
            }
        }

        sqlx::query("DELETE FROM billing_plan_entitlements WHERE plan_key = $1")
            .bind(plan.key().as_str())
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        for grant in plan.entitlements() {
            sqlx::query(
                "INSERT INTO billing_plan_entitlements ( \
                    plan_key, entitlement_key, value_kind, boolean_value, limit_value, \
                    created_at, updated_at \
                 ) VALUES ($1, $2, $3, $4, $5, clock_timestamp(), clock_timestamp())",
            )
            .bind(plan.key().as_str())
            .bind(grant.key().as_str())
            .bind(grant.value().kind())
            .bind(grant.value().boolean())
            .bind(grant.value().limit())
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        }
        self.invalidate_plan_dependents(&mut transaction, plan.key().as_str())
            .await?;
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Global,
                event_type: "billing.plan.updated",
                action: "billing.plan.update",
                resource_kind: "billing_plan",
                resource_id: None,
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(())
    }

    /// Maps an exact provider price identity to an application-owned plan.
    ///
    /// # Errors
    ///
    /// Returns a safe persistence or audit error; missing plans fail closed.
    pub async fn put_price_mapping(
        &self,
        mapping: &ProviderPriceMapping,
    ) -> Result<(), BillingStoreError> {
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        sqlx::query(
            "INSERT INTO billing_provider_prices ( \
                provider, provider_price_id, plan_key, created_at, updated_at \
             ) VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (provider, provider_price_id) DO UPDATE SET \
                plan_key = EXCLUDED.plan_key, updated_at = clock_timestamp()",
        )
        .bind(mapping.provider().as_str())
        .bind(mapping.price_id().as_str())
        .bind(mapping.plan_key().as_str())
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        self.invalidate_price_dependents(
            &mut transaction,
            mapping.provider(),
            mapping.price_id().as_str(),
        )
        .await?;
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Global,
                event_type: "billing.price_mapping.updated",
                action: "billing.price_mapping.update",
                resource_kind: "billing_price_mapping",
                resource_id: None,
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(())
    }

    /// Records and fences a raw-body-verified provider event before any API reconciliation.
    ///
    /// # Errors
    ///
    /// Returns a safe database or audit error. Duplicate, order, and identity conflicts are values
    /// so their committed fail-closed disposition is not rolled back.
    pub async fn enqueue_verified_event(
        &self,
        provider: &ProviderId,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
        fingerprint: [u8; 32],
    ) -> Result<EventEnqueueOutcome, BillingStoreError> {
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        self.ensure_reconciliation_state(&mut transaction, event.tenant_id(), provider)
            .await?;

        if let Some(outcome) = self
            .existing_event_outcome(&mut transaction, provider, event, receipt_id, &fingerprint)
            .await?
        {
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(outcome);
        }

        let sequence = self
            .event_sequence_disposition(&mut transaction, provider, event, receipt_id)
            .await?;
        if sequence == EventSequenceDisposition::Conflict {
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(EventEnqueueOutcome::Conflict);
        }
        let out_of_order = sequence == EventSequenceDisposition::OutOfOrder;
        if !self
            .insert_provider_event(
                &mut transaction,
                provider,
                event,
                receipt_id,
                &fingerprint,
                out_of_order,
            )
            .await?
        {
            transaction
                .rollback()
                .await
                .map_err(BillingStoreError::Database)?;
            return self
                .resolve_provider_event_insert_race(provider, event, receipt_id, &fingerprint)
                .await;
        }

        if out_of_order {
            self.audit_out_of_order_event(&mut transaction, event, receipt_id)
                .await?;
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            counter!("omnius_billing_webhook_events_total", "result" => "out_of_order").increment(1);
            return Ok(EventEnqueueOutcome::OutOfOrder);
        }

        let task_id = self
            .accept_provider_event(&mut transaction, provider, event)
            .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        counter!("omnius_billing_webhook_events_total", "result" => "accepted").increment(1);
        Ok(EventEnqueueOutcome::Enqueued(task_id))
    }

    async fn resolve_provider_event_insert_race(
        &self,
        provider: &ProviderId,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
        fingerprint: &[u8; 32],
    ) -> Result<EventEnqueueOutcome, BillingStoreError> {
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        self.ensure_reconciliation_state(&mut transaction, event.tenant_id(), provider)
            .await?;
        let outcome = if let Some(outcome) = self
            .existing_event_outcome(&mut transaction, provider, event, receipt_id, fingerprint)
            .await?
        {
            outcome
        } else {
            match self
                .event_sequence_disposition(&mut transaction, provider, event, receipt_id)
                .await?
            {
                EventSequenceDisposition::Conflict => EventEnqueueOutcome::Conflict,
                EventSequenceDisposition::Current | EventSequenceDisposition::OutOfOrder => {
                    return Err(BillingStoreError::CorruptState);
                }
            }
        };
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(outcome)
    }

    async fn existing_event_outcome(
        &self,
        connection: &mut PgConnection,
        provider: &ProviderId,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
        fingerprint: &[u8; 32],
    ) -> Result<Option<EventEnqueueOutcome>, BillingStoreError> {
        let Some(row) = sqlx::query(
            "SELECT provider_event_sequence, event_fingerprint, disposition \
             FROM billing_provider_events \
             WHERE tenant_id = $1 AND provider = $2 AND provider_event_id = $3 FOR UPDATE",
        )
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .bind(event.event_id().as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(map_sqlx)?
        else {
            return Ok(None);
        };

        let identical = row.try_get::<i64, _>("provider_event_sequence").ok()
            == Some(event.sequence().get())
            && row
                .try_get::<Vec<u8>, _>("event_fingerprint")
                .ok()
                .as_deref()
                == Some(fingerprint.as_slice());
        if !identical {
            self.audit_event_conflict(connection, event, receipt_id)
                .await?;
            return Ok(Some(EventEnqueueOutcome::Conflict));
        }
        let disposition: String = row
            .try_get("disposition")
            .map_err(|_| BillingStoreError::CorruptState)?;
        if disposition == "out_of_order" {
            return Ok(Some(EventEnqueueOutcome::OutOfOrder));
        }
        let task_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM billing_reconciliation_tasks \
             WHERE tenant_id = $1 AND provider = $2 AND source_event_id = $3",
        )
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .bind(event.event_id().as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        let task_id = ReconciliationTaskId::from_uuid(task_id)
            .map_err(|_| BillingStoreError::CorruptState)?;
        Ok(Some(EventEnqueueOutcome::Duplicate(task_id)))
    }

    async fn event_sequence_disposition(
        &self,
        connection: &mut PgConnection,
        provider: &ProviderId,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
    ) -> Result<EventSequenceDisposition, BillingStoreError> {
        let last_sequence: Option<i64> = sqlx::query_scalar(
            "SELECT last_event_sequence FROM billing_reconciliation_state \
             WHERE tenant_id = $1 AND provider = $2 FOR UPDATE",
        )
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        let sequence_conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM billing_provider_events \
             WHERE tenant_id = $1 AND provider = $2 AND provider_event_sequence = $3 \
                AND provider_event_id <> $4)",
        )
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .bind(event.sequence().get())
        .bind(event.event_id().as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        if sequence_conflict {
            self.audit_event_conflict(connection, event, receipt_id)
                .await?;
            return Ok(EventSequenceDisposition::Conflict);
        }
        if last_sequence.is_some_and(|last| event.sequence().get() <= last) {
            Ok(EventSequenceDisposition::OutOfOrder)
        } else {
            Ok(EventSequenceDisposition::Current)
        }
    }

    async fn insert_provider_event(
        &self,
        connection: &mut PgConnection,
        provider: &ProviderId,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
        fingerprint: &[u8; 32],
        out_of_order: bool,
    ) -> Result<bool, BillingStoreError> {
        let disposition = if out_of_order {
            "out_of_order"
        } else {
            "accepted"
        };
        let result = sqlx::query(
            "INSERT INTO billing_provider_events ( \
                tenant_id, provider, provider_event_id, provider_event_sequence, receipt_id, \
                event_fingerprint, disposition, received_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp())",
        )
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .bind(event.event_id().as_str())
        .bind(event.sequence().get())
        .bind(receipt_id.as_uuid())
        .bind(fingerprint.as_slice())
        .bind(disposition)
        .execute(&mut *connection)
        .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) if is_unique_violation(&error) => Ok(false),
            Err(error) => Err(map_sqlx(error)),
        }
    }

    async fn audit_event_conflict(
        &self,
        connection: &mut PgConnection,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
    ) -> Result<(), BillingStoreError> {
        self.append_audit(
            connection,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(event.tenant_id()),
                event_type: "billing.webhook.conflict",
                action: "billing.webhook.reconcile",
                resource_kind: "billing_provider_event",
                resource_id: Some(receipt_id.as_uuid().to_string()),
                outcome: AuditOutcome::Denied,
            },
        )
        .await
    }

    async fn audit_out_of_order_event(
        &self,
        connection: &mut PgConnection,
        event: &ProviderEvent,
        receipt_id: ReceiptId,
    ) -> Result<(), BillingStoreError> {
        self.append_audit(
            connection,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(event.tenant_id()),
                event_type: "billing.webhook.out_of_order",
                action: "billing.webhook.reconcile",
                resource_kind: "billing_provider_event",
                resource_id: Some(receipt_id.as_uuid().to_string()),
                outcome: AuditOutcome::Denied,
            },
        )
        .await
    }

    async fn accept_provider_event(
        &self,
        connection: &mut PgConnection,
        provider: &ProviderId,
        event: &ProviderEvent,
    ) -> Result<ReconciliationTaskId, BillingStoreError> {
        sqlx::query(
            "UPDATE billing_reconciliation_state SET \
                last_event_sequence = $3, updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .bind(event.sequence().get())
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        let task_id = ReconciliationTaskId::new();
        sqlx::query(
            "INSERT INTO billing_reconciliation_tasks ( \
                id, tenant_id, provider, reason, source_event_id, status, available_at, \
                created_at, updated_at \
             ) VALUES ($1, $2, $3, 'webhook', $4, 'pending', clock_timestamp(), \
                clock_timestamp(), clock_timestamp())",
        )
        .bind(task_id.as_uuid())
        .bind(event.tenant_id().as_uuid())
        .bind(provider.as_str())
        .bind(event.event_id().as_str())
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        self.append_audit(
            connection,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(event.tenant_id()),
                event_type: "billing.webhook.accepted",
                action: "billing.webhook.reconcile",
                resource_kind: "billing_reconciliation",
                resource_id: Some(task_id.as_uuid().to_string()),
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        Ok(task_id)
    }

    /// Enqueues an idempotent tenant-authorized repair and appends its audit event atomically.
    ///
    /// # Errors
    ///
    /// Returns a safe database, provider-conflict, or audit error.
    pub async fn request_repair(
        &self,
        context: &TenantContext,
        provider: &ProviderId,
        idempotency_key: &RepairIdempotencyKey,
    ) -> Result<RepairEnqueueOutcome, BillingStoreError> {
        let tenant_id = context.membership().organization_id;
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        self.ensure_reconciliation_state(&mut transaction, tenant_id, provider)
            .await?;
        let id = ReconciliationTaskId::new();
        let inserted = sqlx::query(
            "INSERT INTO billing_reconciliation_tasks ( \
                id, tenant_id, provider, reason, repair_idempotency_key, status, available_at, \
                created_at, updated_at \
             ) VALUES ($1, $2, $3, 'repair', $4, 'pending', clock_timestamp(), \
                clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (tenant_id, provider, repair_idempotency_key) \
                WHERE repair_idempotency_key IS NOT NULL DO NOTHING",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(provider.as_str())
        .bind(idempotency_key.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if inserted.rows_affected() == 0 {
            let existing: Uuid = sqlx::query_scalar(
                "SELECT id FROM billing_reconciliation_tasks \
                 WHERE tenant_id = $1 AND provider = $2 AND repair_idempotency_key = $3",
            )
            .bind(tenant_id.as_uuid())
            .bind(provider.as_str())
            .bind(idempotency_key.as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let existing = ReconciliationTaskId::from_uuid(existing)
                .map_err(|_| BillingStoreError::CorruptState)?;
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(RepairEnqueueOutcome::Duplicate(existing));
        }
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: principal_actor(context.principal()),
                scope: AuditScope::Tenant(tenant_id),
                event_type: "billing.repair.requested",
                action: "billing.repair.request",
                resource_kind: "billing_reconciliation",
                resource_id: Some(id.as_uuid().to_string()),
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(RepairEnqueueOutcome::Enqueued(id))
    }

    /// Claims one named ready or expired reconciliation under a fresh `UUIDv7` lease token.
    ///
    /// # Errors
    ///
    /// Returns a safe database or row-decoding error.
    pub async fn claim_task(
        &self,
        id: ReconciliationTaskId,
    ) -> Result<Option<ClaimedReconciliation>, BillingStoreError> {
        let lease_token = Uuid::now_v7();
        let lease_micros = duration_micros(self.config.reconciliation_lease)?;
        let max_attempts = i32::from(self.config.max_attempts);
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let exhausted_tenant: Option<Uuid> = sqlx::query_scalar(
            "UPDATE billing_reconciliation_tasks SET status = 'dead_letter', \
                lease_token = NULL, lease_expires_at = NULL, \
                last_error_class = COALESCE(last_error_class, 'attempts_exhausted'), \
                dead_lettered_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE id = $1 AND attempt_count >= $2 AND (status = 'pending' \
                OR (status = 'processing' AND lease_expires_at <= clock_timestamp())) \
             RETURNING tenant_id",
        )
        .bind(id.as_uuid())
        .bind(max_attempts)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if let Some(tenant_id) = exhausted_tenant {
            let tenant_id =
                TenantId::from_uuid(tenant_id).map_err(|_| BillingStoreError::CorruptState)?;
            self.append_audit(
                &mut transaction,
                AuditRecord {
                    actor: AuditActor::System,
                    scope: AuditScope::Tenant(tenant_id),
                    event_type: "billing.reconciliation.dead_lettered",
                    action: "billing.reconciliation.process",
                    resource_kind: "billing_reconciliation",
                    resource_id: Some(id.as_uuid().to_string()),
                    outcome: AuditOutcome::Failed,
                },
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(None);
        }
        let row = sqlx::query(
            "UPDATE billing_reconciliation_tasks SET \
                status = 'processing', attempt_count = attempt_count + 1, lease_token = $2, \
                lease_expires_at = clock_timestamp() + ($3 * interval '1 microsecond'), \
                updated_at = clock_timestamp(), last_error_class = NULL \
             WHERE id = $1 AND attempt_count < $4 AND ( \
                (status = 'pending' AND available_at <= clock_timestamp()) \
                OR (status = 'processing' AND lease_expires_at <= clock_timestamp()) \
             ) RETURNING tenant_id, provider, lease_expires_at, attempt_count",
        )
        .bind(id.as_uuid())
        .bind(lease_token)
        .bind(lease_micros)
        .bind(max_attempts)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let claim = row
            .map(|row| claimed_from_row(id, lease_token, &row))
            .transpose()?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(claim)
    }

    /// Returns whether a durable reconciliation task reached completed or dead-letter state.
    ///
    /// # Errors
    ///
    /// Returns a safe not-found or database error.
    pub async fn task_is_terminal(
        &self,
        id: ReconciliationTaskId,
    ) -> Result<bool, BillingStoreError> {
        let mut connection = self.acquire().await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM billing_reconciliation_tasks WHERE id = $1")
                .bind(id.as_uuid())
                .fetch_optional(&mut *connection)
                .await
                .map_err(map_sqlx)?;
        status
            .map(|value| matches!(value.as_str(), "completed" | "dead_letter"))
            .ok_or(BillingStoreError::NotFound)
    }

    /// Claims a bounded batch of ready or expired reconciliation work with disjoint row locks.
    ///
    /// # Errors
    ///
    /// Returns a safe database or row-decoding error.
    pub async fn claim_ready(
        &self,
        provider: &ProviderId,
    ) -> Result<Vec<ClaimedReconciliation>, BillingStoreError> {
        let lease_micros = duration_micros(self.config.reconciliation_lease)?;
        let max_attempts = i32::from(self.config.max_attempts);
        let limit = i64::from(self.config.claim_batch);
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let exhausted_rows = sqlx::query(
            "WITH exhausted AS ( \
                SELECT id FROM billing_reconciliation_tasks \
                WHERE provider = $3 AND attempt_count >= $1 AND (status = 'pending' \
                    OR (status = 'processing' AND lease_expires_at <= clock_timestamp())) \
                ORDER BY updated_at, id LIMIT $2 FOR UPDATE SKIP LOCKED \
             ) UPDATE billing_reconciliation_tasks AS task SET status = 'dead_letter', \
                lease_token = NULL, lease_expires_at = NULL, \
                last_error_class = COALESCE(task.last_error_class, 'attempts_exhausted'), \
                dead_lettered_at = clock_timestamp(), updated_at = clock_timestamp() \
             FROM exhausted WHERE task.id = exhausted.id RETURNING task.id, task.tenant_id",
        )
        .bind(max_attempts)
        .bind(limit)
        .bind(provider.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        for row in exhausted_rows {
            let task_id: Uuid = row
                .try_get("id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let tenant_id: Uuid = row
                .try_get("tenant_id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let tenant_id =
                TenantId::from_uuid(tenant_id).map_err(|_| BillingStoreError::CorruptState)?;
            self.append_audit(
                &mut transaction,
                AuditRecord {
                    actor: AuditActor::System,
                    scope: AuditScope::Tenant(tenant_id),
                    event_type: "billing.reconciliation.dead_lettered",
                    action: "billing.reconciliation.process",
                    resource_kind: "billing_reconciliation",
                    resource_id: Some(task_id.to_string()),
                    outcome: AuditOutcome::Failed,
                },
            )
            .await?;
        }
        let rows = sqlx::query(
            "SELECT id FROM billing_reconciliation_tasks \
             WHERE provider = $3 AND attempt_count < $1 AND ( \
                (status = 'pending' AND available_at <= clock_timestamp()) \
                OR (status = 'processing' AND lease_expires_at <= clock_timestamp()) \
             ) ORDER BY available_at, id FOR UPDATE SKIP LOCKED LIMIT $2",
        )
        .bind(max_attempts)
        .bind(limit)
        .bind(provider.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let id_uuid: Uuid = row
                .try_get("id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let id = ReconciliationTaskId::from_uuid(id_uuid)
                .map_err(|_| BillingStoreError::CorruptState)?;
            let lease_token = Uuid::now_v7();
            let claimed = sqlx::query(
                "UPDATE billing_reconciliation_tasks SET \
                    status = 'processing', attempt_count = attempt_count + 1, lease_token = $2, \
                    lease_expires_at = clock_timestamp() + ($3 * interval '1 microsecond'), \
                    updated_at = clock_timestamp(), last_error_class = NULL \
                 WHERE id = $1 \
                 RETURNING tenant_id, provider, lease_expires_at, attempt_count",
            )
            .bind(id.as_uuid())
            .bind(lease_token)
            .bind(lease_micros)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            claims.push(claimed_from_row(id, lease_token, &claimed)?);
        }
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(claims)
    }

    /// Requeues a retryable task only while the exact database lease remains live.
    ///
    /// # Errors
    ///
    /// Returns [`BillingStoreError::LostLease`] for expired or replaced tokens.
    pub async fn retry_task(
        &self,
        claim: &ClaimedReconciliation,
        failure_class: &str,
    ) -> Result<(), BillingStoreError> {
        if !safe_failure_class(failure_class) {
            return Err(BillingStoreError::InvalidValue);
        }
        if claim.attempt_count >= self.config.max_attempts {
            return self.dead_letter_task(claim, failure_class).await;
        }
        let retry_micros = duration_micros(self.config.retry_delay)?;
        let mut connection = self.acquire().await?;
        let result = sqlx::query(
            "UPDATE billing_reconciliation_tasks SET \
                status = 'pending', available_at = clock_timestamp() + ($3 * interval '1 microsecond'), \
                lease_token = NULL, lease_expires_at = NULL, last_error_class = $4, \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND lease_token = $2 AND status = 'processing' \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.id.as_uuid())
        .bind(claim.lease_token)
        .bind(retry_micros)
        .bind(failure_class)
        .execute(&mut *connection)
        .await.map_err(map_sqlx)?;
        require_fence(result.rows_affected())
    }

    /// Dead-letters a permanent task only while the exact database lease remains live.
    ///
    /// # Errors
    ///
    /// Returns [`BillingStoreError::LostLease`] for expired or replaced tokens.
    pub async fn dead_letter_task(
        &self,
        claim: &ClaimedReconciliation,
        failure_class: &str,
    ) -> Result<(), BillingStoreError> {
        if !safe_failure_class(failure_class) {
            return Err(BillingStoreError::InvalidValue);
        }
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let result = sqlx::query(
            "UPDATE billing_reconciliation_tasks SET \
                status = 'dead_letter', lease_token = NULL, lease_expires_at = NULL, \
                last_error_class = $3, dead_lettered_at = clock_timestamp(), \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND lease_token = $2 AND status = 'processing' \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.id.as_uuid())
        .bind(claim.lease_token)
        .bind(failure_class)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        require_fence(result.rows_affected())?;
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(claim.tenant_id),
                event_type: "billing.reconciliation.dead_lettered",
                action: "billing.reconciliation.process",
                resource_kind: "billing_reconciliation",
                resource_id: Some(claim.id.as_uuid().to_string()),
                outcome: AuditOutcome::Failed,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)
    }

    /// Publishes a verified API snapshot, local entitlement evaluation, audit, and outbox event in
    /// one fenced PostgreSQL transaction.
    ///
    /// # Errors
    ///
    /// Returns a safe lost-lease, provider mismatch, constraint, encoding, audit, or database error.
    pub async fn apply_snapshot(
        &self,
        claim: &ClaimedReconciliation,
        snapshot: &ProviderSnapshot,
    ) -> Result<SnapshotApplyOutcome, BillingStoreError> {
        if snapshot.tenant_id() != claim.tenant_id || snapshot.provider() != &claim.provider {
            return Err(BillingStoreError::ProviderMismatch);
        }
        let fingerprint = snapshot_fingerprint(snapshot)?;
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        self.require_live_task(&mut transaction, claim).await?;
        let disposition = self
            .snapshot_revision_disposition(&mut transaction, claim, snapshot, &fingerprint)
            .await?;
        if disposition != SnapshotRevisionDisposition::Publish {
            self.finalize_nonpublishing_snapshot(&mut transaction, claim, disposition)
                .await?;
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return match disposition {
                SnapshotRevisionDisposition::Stale => Ok(SnapshotApplyOutcome::Stale),
                SnapshotRevisionDisposition::Duplicate => Ok(SnapshotApplyOutcome::Duplicate),
                SnapshotRevisionDisposition::Conflict => {
                    counter!("omnius_billing_reconciliations_total", "result" => "conflict")
                        .increment(1);
                    Ok(SnapshotApplyOutcome::Conflict)
                }
                SnapshotRevisionDisposition::Publish => Err(BillingStoreError::InvalidSnapshot),
            };
        }

        let entitlement_count = self
            .publish_snapshot(&mut transaction, claim, snapshot, &fingerprint)
            .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        counter!("omnius_billing_reconciliations_total", "result" => "applied").increment(1);
        Ok(SnapshotApplyOutcome::Applied { entitlement_count })
    }

    async fn snapshot_revision_disposition(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
        snapshot: &ProviderSnapshot,
        fingerprint: &[u8; 32],
    ) -> Result<SnapshotRevisionDisposition, BillingStoreError> {
        let row = sqlx::query(
            "SELECT last_reconciliation_revision, last_snapshot_fingerprint \
             FROM billing_reconciliation_state \
             WHERE tenant_id = $1 AND provider = $2 FOR UPDATE",
        )
        .bind(claim.tenant_id.as_uuid())
        .bind(claim.provider.as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        let last_revision: Option<i64> = row
            .try_get("last_reconciliation_revision")
            .map_err(|_| BillingStoreError::CorruptState)?;
        let last_fingerprint: Option<Vec<u8>> = row
            .try_get("last_snapshot_fingerprint")
            .map_err(|_| BillingStoreError::CorruptState)?;
        let Some(last_revision) = last_revision else {
            return Ok(SnapshotRevisionDisposition::Publish);
        };
        if snapshot.revision().get() < last_revision {
            return Ok(SnapshotRevisionDisposition::Stale);
        }
        if snapshot.revision().get() > last_revision {
            return Ok(SnapshotRevisionDisposition::Publish);
        }
        if last_fingerprint.as_deref() == Some(fingerprint.as_slice()) {
            Ok(SnapshotRevisionDisposition::Duplicate)
        } else {
            Ok(SnapshotRevisionDisposition::Conflict)
        }
    }

    async fn finalize_nonpublishing_snapshot(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
        disposition: SnapshotRevisionDisposition,
    ) -> Result<(), BillingStoreError> {
        let (event_type, outcome) = match disposition {
            SnapshotRevisionDisposition::Stale => {
                self.complete_task(connection, claim).await?;
                ("billing.reconciliation.stale", AuditOutcome::Denied)
            }
            SnapshotRevisionDisposition::Duplicate => {
                self.complete_task(connection, claim).await?;
                ("billing.reconciliation.duplicate", AuditOutcome::Succeeded)
            }
            SnapshotRevisionDisposition::Conflict => {
                self.dead_letter_in_transaction(connection, claim, FAILURE_SNAPSHOT_CONFLICT)
                    .await?;
                ("billing.reconciliation.conflict", AuditOutcome::Failed)
            }
            SnapshotRevisionDisposition::Publish => {
                return Err(BillingStoreError::InvalidSnapshot);
            }
        };
        self.append_audit(
            connection,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(claim.tenant_id),
                event_type,
                action: "billing.reconciliation.publish",
                resource_kind: "billing_reconciliation",
                resource_id: Some(claim.id.as_uuid().to_string()),
                outcome,
            },
        )
        .await
    }

    async fn publish_snapshot(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
        snapshot: &ProviderSnapshot,
        fingerprint: &[u8; 32],
    ) -> Result<u64, BillingStoreError> {
        self.replace_mirrors(connection, snapshot).await?;
        let entitlement_count = self
            .replace_effective_entitlements(connection, snapshot)
            .await?;
        sqlx::query(
            "UPDATE billing_reconciliation_state SET \
                last_reconciliation_revision = $3, last_snapshot_fingerprint = $4, \
                reconciled_at = $5, updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(claim.tenant_id.as_uuid())
        .bind(claim.provider.as_str())
        .bind(snapshot.revision().get())
        .bind(fingerprint.as_slice())
        .bind(snapshot.observed_at())
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        self.complete_task(connection, claim).await?;
        self.append_audit(
            connection,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(claim.tenant_id),
                event_type: "billing.reconciliation.published",
                action: "billing.reconciliation.publish",
                resource_kind: "billing_reconciliation",
                resource_id: Some(claim.id.as_uuid().to_string()),
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        self.append_entitlements_event(
            connection,
            claim,
            snapshot.revision(),
            entitlement_count,
            snapshot.observed_at(),
        )
        .await?;
        Ok(entitlement_count)
    }

    /// Reads effective entitlements only from tenant-scoped reconciled local state.
    ///
    /// # Errors
    ///
    /// Returns a safe database or bounded-row decoding error.
    pub async fn entitlements(
        &self,
        context: &TenantContext,
    ) -> Result<Vec<EffectiveEntitlement>, BillingStoreError> {
        let tenant_id = context.membership().organization_id;
        let mut connection = self.acquire().await?;
        let rows = sqlx::query(
            "SELECT entitlement_key, value_kind, boolean_value, limit_value, provider, \
                provider_revision, valid_until, in_grace \
             FROM billing_entitlements WHERE tenant_id = $1 \
                AND (valid_until IS NULL OR valid_until > clock_timestamp()) \
             ORDER BY entitlement_key LIMIT $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(i64::try_from(MAX_EFFECTIVE_ENTITLEMENTS + 1).unwrap_or(i64::MAX))
        .fetch_all(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        if u64::try_from(rows.len()).unwrap_or(u64::MAX) > MAX_EFFECTIVE_ENTITLEMENTS {
            return Err(BillingStoreError::CorruptState);
        }
        rows.iter().map(entitlement_from_row).collect()
    }

    /// Records one tenant-scoped usage fact using a database unique constraint as its concurrency
    /// fence and appends the audit event in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns a safe database or audit error. Exact duplicates and conflicts are values.
    pub async fn record_usage(
        &self,
        context: &TenantContext,
        provider: &ProviderId,
        usage: &NewUsageRecord,
    ) -> Result<UsageRecordOutcome, BillingStoreError> {
        let tenant_id = context.membership().organization_id;
        let fingerprint = usage_fingerprint(tenant_id, provider, usage);
        let id = UsageRecordId::new();
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let database_now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        if usage.occurred_at() > database_now + MAX_USAGE_FUTURE_SKEW {
            return Err(BillingStoreError::InvalidValue);
        }
        let inserted = sqlx::query(
            "INSERT INTO billing_usage ( \
                id, tenant_id, provider, meter_key, idempotency_key, request_fingerprint, \
                quantity, occurred_at, status, created_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', \
                clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (tenant_id, meter_key, idempotency_key) DO NOTHING",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(provider.as_str())
        .bind(usage.meter().as_str())
        .bind(usage.idempotency_key().as_str())
        .bind(fingerprint.as_slice())
        .bind(i64::try_from(usage.quantity()).map_err(|_| BillingStoreError::InvalidValue)?)
        .bind(usage.occurred_at())
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if inserted.rows_affected() == 0 {
            let row = sqlx::query(
                "SELECT id, request_fingerprint FROM billing_usage \
                 WHERE tenant_id = $1 AND meter_key = $2 AND idempotency_key = $3 FOR UPDATE",
            )
            .bind(tenant_id.as_uuid())
            .bind(usage.meter().as_str())
            .bind(usage.idempotency_key().as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let existing_id: Uuid = row
                .try_get("id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let existing_fingerprint: Vec<u8> = row
                .try_get("request_fingerprint")
                .map_err(|_| BillingStoreError::CorruptState)?;
            if existing_fingerprint.as_slice() == fingerprint {
                transaction
                    .commit()
                    .await
                    .map_err(BillingStoreError::Database)?;
                return UsageRecordId::from_uuid(existing_id)
                    .map(UsageRecordOutcome::Duplicate)
                    .map_err(|_| BillingStoreError::CorruptState);
            }
            self.append_audit(
                &mut transaction,
                AuditRecord {
                    actor: principal_actor(context.principal()),
                    scope: AuditScope::Tenant(tenant_id),
                    event_type: "billing.usage.conflict",
                    action: "billing.usage.record",
                    resource_kind: "billing_usage",
                    resource_id: Some(existing_id.to_string()),
                    outcome: AuditOutcome::Denied,
                },
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(UsageRecordOutcome::Conflict);
        }
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: principal_actor(context.principal()),
                scope: AuditScope::Tenant(tenant_id),
                event_type: "billing.usage.recorded",
                action: "billing.usage.record",
                resource_kind: "billing_usage",
                resource_id: Some(id.as_uuid().to_string()),
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        counter!("omnius_billing_usage_total", "result" => "recorded").increment(1);
        Ok(UsageRecordOutcome::Recorded(id))
    }

    /// Claims one named pending or expired usage record under a fresh `UUIDv7` lease.
    ///
    /// # Errors
    ///
    /// Returns a safe database or bounded-row decoding error.
    pub async fn claim_usage(
        &self,
        record_id: UsageRecordId,
    ) -> Result<Option<ClaimedUsage>, BillingStoreError> {
        let lease_token = Uuid::now_v7();
        let lease_micros = duration_micros(self.config.reconciliation_lease)?;
        let max_attempts = i32::from(self.config.max_attempts);
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let exhausted_tenant: Option<Uuid> = sqlx::query_scalar(
            "UPDATE billing_usage SET status = 'rejected', lease_token = NULL, \
                lease_expires_at = NULL, \
                last_error_class = COALESCE(last_error_class, 'attempts_exhausted'), \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND attempt_count >= $2 AND (status = 'pending' \
                OR (status = 'processing' AND lease_expires_at <= clock_timestamp())) \
             RETURNING tenant_id",
        )
        .bind(record_id.as_uuid())
        .bind(max_attempts)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if let Some(tenant_id) = exhausted_tenant {
            let tenant_id =
                TenantId::from_uuid(tenant_id).map_err(|_| BillingStoreError::CorruptState)?;
            self.append_audit(
                &mut transaction,
                AuditRecord {
                    actor: AuditActor::System,
                    scope: AuditScope::Tenant(tenant_id),
                    event_type: "billing.usage.rejected",
                    action: "billing.usage.submit",
                    resource_kind: "billing_usage",
                    resource_id: Some(record_id.as_uuid().to_string()),
                    outcome: AuditOutcome::Failed,
                },
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(None);
        }
        let row = sqlx::query(
            "UPDATE billing_usage SET status = 'processing', \
                attempt_count = attempt_count + 1, lease_token = $2, \
                lease_expires_at = clock_timestamp() + ($3 * interval '1 microsecond'), \
                updated_at = clock_timestamp(), last_error_class = NULL \
             WHERE id = $1 AND attempt_count < $4 AND ( \
                (status = 'pending' AND available_at <= clock_timestamp()) \
                OR (status = 'processing' AND lease_expires_at <= clock_timestamp()) \
             ) RETURNING tenant_id, provider, meter_key, idempotency_key, quantity, occurred_at, \
                lease_expires_at, attempt_count",
        )
        .bind(record_id.as_uuid())
        .bind(lease_token)
        .bind(lease_micros)
        .bind(max_attempts)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let claim = row
            .map(|row| claimed_usage_from_row(record_id, lease_token, &row))
            .transpose()?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(claim)
    }

    /// Claims a bounded batch of pending or expired usage submissions for durable redrive.
    ///
    /// # Errors
    ///
    /// Returns a safe database or bounded-row decoding error.
    pub async fn claim_ready_usage(
        &self,
        provider: &ProviderId,
    ) -> Result<Vec<ClaimedUsage>, BillingStoreError> {
        let lease_micros = duration_micros(self.config.reconciliation_lease)?;
        let max_attempts = i32::from(self.config.max_attempts);
        let limit = i64::from(self.config.claim_batch);
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let exhausted_rows = sqlx::query(
            "WITH exhausted AS (SELECT id FROM billing_usage \
                WHERE provider = $3 AND attempt_count >= $1 AND (status = 'pending' \
                    OR (status = 'processing' AND lease_expires_at <= clock_timestamp())) \
                ORDER BY updated_at, id LIMIT $2 FOR UPDATE SKIP LOCKED) \
             UPDATE billing_usage AS usage SET status = 'rejected', lease_token = NULL, \
                lease_expires_at = NULL, \
                last_error_class = COALESCE(usage.last_error_class, 'attempts_exhausted'), \
                updated_at = clock_timestamp() \
             FROM exhausted WHERE usage.id = exhausted.id RETURNING usage.id, usage.tenant_id",
        )
        .bind(max_attempts)
        .bind(limit)
        .bind(provider.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        for row in exhausted_rows {
            let usage_id: Uuid = row
                .try_get("id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let tenant_id: Uuid = row
                .try_get("tenant_id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let tenant_id =
                TenantId::from_uuid(tenant_id).map_err(|_| BillingStoreError::CorruptState)?;
            self.append_audit(
                &mut transaction,
                AuditRecord {
                    actor: AuditActor::System,
                    scope: AuditScope::Tenant(tenant_id),
                    event_type: "billing.usage.rejected",
                    action: "billing.usage.submit",
                    resource_kind: "billing_usage",
                    resource_id: Some(usage_id.to_string()),
                    outcome: AuditOutcome::Failed,
                },
            )
            .await?;
        }
        let rows = sqlx::query(
            "SELECT id FROM billing_usage WHERE provider = $3 AND attempt_count < $1 AND ( \
                (status = 'pending' AND available_at <= clock_timestamp()) \
                OR (status = 'processing' AND lease_expires_at <= clock_timestamp()) \
             ) ORDER BY available_at, id FOR UPDATE SKIP LOCKED LIMIT $2",
        )
        .bind(max_attempts)
        .bind(limit)
        .bind(provider.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row
                .try_get("id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let record_id =
                UsageRecordId::from_uuid(id).map_err(|_| BillingStoreError::CorruptState)?;
            let lease_token = Uuid::now_v7();
            let claimed = sqlx::query(
                "UPDATE billing_usage SET status = 'processing', \
                    attempt_count = attempt_count + 1, lease_token = $2, \
                    lease_expires_at = clock_timestamp() + ($3 * interval '1 microsecond'), \
                    updated_at = clock_timestamp(), last_error_class = NULL \
                 WHERE id = $1 RETURNING tenant_id, provider, meter_key, idempotency_key, \
                    quantity, occurred_at, lease_expires_at, attempt_count",
            )
            .bind(record_id.as_uuid())
            .bind(lease_token)
            .bind(lease_micros)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            claims.push(claimed_usage_from_row(record_id, lease_token, &claimed)?);
        }
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(claims)
    }

    /// Returns the durable state of one tenant-scoped usage record.
    ///
    /// # Errors
    ///
    /// Returns a safe database, not-found, or corrupt-state error.
    pub async fn usage_state(
        &self,
        tenant_id: TenantId,
        record_id: UsageRecordId,
    ) -> Result<UsageRecordState, BillingStoreError> {
        let mut connection = self.acquire().await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM billing_usage WHERE id = $1 AND tenant_id = $2")
                .bind(record_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .fetch_optional(&mut *connection)
                .await
                .map_err(map_sqlx)?;
        match status.as_deref() {
            Some("accepted") => Ok(UsageRecordState::Accepted),
            Some("rejected") => Ok(UsageRecordState::Rejected),
            Some("pending" | "processing") => Ok(UsageRecordState::Pending),
            Some(_) => Err(BillingStoreError::CorruptState),
            None => Err(BillingStoreError::NotFound),
        }
    }

    /// Requeues one retryable usage submission while its exact lease is live.
    ///
    /// # Errors
    ///
    /// Returns [`BillingStoreError::LostLease`] for expired or replaced tokens.
    pub async fn retry_usage(
        &self,
        claim: &ClaimedUsage,
        failure_class: &str,
    ) -> Result<(), BillingStoreError> {
        if !safe_failure_class(failure_class) {
            return Err(BillingStoreError::InvalidValue);
        }
        if claim.attempt_count >= self.config.max_attempts {
            return self.reject_usage(claim, failure_class).await;
        }
        let retry_micros = duration_micros(self.config.retry_delay)?;
        let mut connection = self.acquire().await?;
        let result = sqlx::query(
            "UPDATE billing_usage SET status = 'pending', \
                available_at = clock_timestamp() + ($3 * interval '1 microsecond'), \
                lease_token = NULL, lease_expires_at = NULL, last_error_class = $4, \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND status = 'processing' AND lease_token = $2 \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.request.record_id().as_uuid())
        .bind(claim.lease_token)
        .bind(retry_micros)
        .bind(failure_class)
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        require_fence(result.rows_affected())
    }

    /// Rejects one permanently failed usage submission while its exact lease is live.
    ///
    /// # Errors
    ///
    /// Returns a safe lease, audit, or database error.
    pub async fn reject_usage(
        &self,
        claim: &ClaimedUsage,
        failure_class: &str,
    ) -> Result<(), BillingStoreError> {
        if !safe_failure_class(failure_class) {
            return Err(BillingStoreError::InvalidValue);
        }
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let result = sqlx::query(
            "UPDATE billing_usage SET status = 'rejected', lease_token = NULL, \
                lease_expires_at = NULL, last_error_class = $3, updated_at = clock_timestamp() \
             WHERE id = $1 AND status = 'processing' AND lease_token = $2 \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.request.record_id().as_uuid())
        .bind(claim.lease_token)
        .bind(failure_class)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        require_fence(result.rows_affected())?;
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(claim.request.tenant_id()),
                event_type: "billing.usage.rejected",
                action: "billing.usage.submit",
                resource_kind: "billing_usage",
                resource_id: Some(claim.request.record_id().as_uuid().to_string()),
                outcome: AuditOutcome::Failed,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)
    }

    /// Marks leased local usage accepted only after exact provider acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a safe lease, audit, or database error.
    pub async fn complete_usage(
        &self,
        claim: &ClaimedUsage,
        acknowledgement: &UsageAcknowledgement,
    ) -> Result<UsageCompletionOutcome, BillingStoreError> {
        let mut connection = self.acquire().await?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(BillingStoreError::Database)?;
        let result = sqlx::query(
            "UPDATE billing_usage SET status = 'accepted', lease_token = NULL, \
                lease_expires_at = NULL, provider_usage_id = $3, provider_accepted_at = $4, \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND status = 'processing' AND lease_token = $2 \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.request.record_id().as_uuid())
        .bind(claim.lease_token)
        .bind(acknowledgement.provider_usage_id().as_str())
        .bind(acknowledgement.accepted_at())
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            let row = sqlx::query(
                "SELECT status, provider_usage_id, provider_accepted_at FROM billing_usage \
                 WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            )
            .bind(claim.request.record_id().as_uuid())
            .bind(claim.request.tenant_id().as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let outcome = match row {
                Some(row) => {
                    let status: String = row
                        .try_get("status")
                        .map_err(|_| BillingStoreError::CorruptState)?;
                    match status.as_str() {
                        "accepted" => {
                            let provider_usage_id: Option<String> = row
                                .try_get("provider_usage_id")
                                .map_err(|_| BillingStoreError::CorruptState)?;
                            let provider_accepted_at: Option<OffsetDateTime> = row
                                .try_get("provider_accepted_at")
                                .map_err(|_| BillingStoreError::CorruptState)?;
                            if provider_usage_id.as_deref()
                                == Some(acknowledgement.provider_usage_id().as_str())
                                && provider_accepted_at
                                    .map(|value| value.unix_timestamp_nanos() / 1_000)
                                    == Some(
                                        acknowledgement.accepted_at().unix_timestamp_nanos()
                                            / 1_000,
                                    )
                            {
                                UsageCompletionOutcome::Duplicate
                            } else {
                                UsageCompletionOutcome::Conflict
                            }
                        }
                        "rejected" => UsageCompletionOutcome::Conflict,
                        "pending" | "processing" => {
                            return Err(BillingStoreError::LostLease);
                        }
                        _ => return Err(BillingStoreError::CorruptState),
                    }
                }
                None => return Err(BillingStoreError::NotFound),
            };
            transaction
                .commit()
                .await
                .map_err(BillingStoreError::Database)?;
            return Ok(outcome);
        }
        self.append_audit(
            &mut transaction,
            AuditRecord {
                actor: AuditActor::System,
                scope: AuditScope::Tenant(claim.request.tenant_id()),
                event_type: "billing.usage.accepted",
                action: "billing.usage.submit",
                resource_kind: "billing_usage",
                resource_id: Some(claim.request.record_id().as_uuid().to_string()),
                outcome: AuditOutcome::Succeeded,
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(BillingStoreError::Database)?;
        Ok(UsageCompletionOutcome::Accepted)
    }
    async fn invalidate_plan_dependents(
        &self,
        connection: &mut PgConnection,
        plan_key: &str,
    ) -> Result<(), BillingStoreError> {
        let rows = sqlx::query(
            "SELECT DISTINCT subscriptions.tenant_id, subscriptions.provider \
             FROM billing_subscriptions AS subscriptions \
             JOIN billing_provider_prices AS prices \
               ON prices.provider = subscriptions.provider \
              AND prices.provider_price_id = subscriptions.provider_price_id \
             WHERE prices.plan_key = $1",
        )
        .bind(plan_key)
        .fetch_all(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        self.invalidate_entitlement_dependents(connection, &rows)
            .await
    }

    async fn invalidate_price_dependents(
        &self,
        connection: &mut PgConnection,
        provider: &ProviderId,
        price_id: &str,
    ) -> Result<(), BillingStoreError> {
        let rows = sqlx::query(
            "SELECT DISTINCT tenant_id, provider FROM billing_subscriptions \
             WHERE provider = $1 AND provider_price_id = $2",
        )
        .bind(provider.as_str())
        .bind(price_id)
        .fetch_all(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        self.invalidate_entitlement_dependents(connection, &rows)
            .await
    }

    async fn invalidate_entitlement_dependents(
        &self,
        connection: &mut PgConnection,
        rows: &[sqlx::postgres::PgRow],
    ) -> Result<(), BillingStoreError> {
        for row in rows {
            let tenant_id: Uuid = row
                .try_get("tenant_id")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let provider: String = row
                .try_get("provider")
                .map_err(|_| BillingStoreError::CorruptState)?;
            let invalidated = sqlx::query(
                "UPDATE billing_reconciliation_state SET \
                    last_reconciliation_revision = NULL, last_snapshot_fingerprint = NULL, \
                    reconciled_at = NULL, updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND provider = $2",
            )
            .bind(tenant_id)
            .bind(&provider)
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
            if invalidated.rows_affected() != 1 {
                return Err(BillingStoreError::CorruptState);
            }
            sqlx::query("DELETE FROM billing_entitlements WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *connection)
                .await
                .map_err(map_sqlx)?;
            let task_id = ReconciliationTaskId::new();
            sqlx::query(
                "INSERT INTO billing_reconciliation_tasks ( \
                    id, tenant_id, provider, reason, status, available_at, created_at, updated_at \
                 ) VALUES ($1, $2, $3, 'scheduled', 'pending', clock_timestamp(), \
                    clock_timestamp(), clock_timestamp())",
            )
            .bind(task_id.as_uuid())
            .bind(tenant_id)
            .bind(&provider)
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
        }
        Ok(())
    }

    async fn acquire(&self) -> Result<omnius_postgres::PostgresConnection, BillingStoreError> {
        self.pool
            .acquire()
            .await
            .map_err(BillingStoreError::Connection)
    }

    async fn ensure_reconciliation_state(
        &self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        provider: &ProviderId,
    ) -> Result<(), BillingStoreError> {
        sqlx::query(
            "INSERT INTO billing_reconciliation_state (tenant_id, provider, updated_at) \
             VALUES ($1, $2, clock_timestamp()) ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id.as_uuid())
        .bind(provider.as_str())
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        let stored: String = sqlx::query_scalar(
            "SELECT provider FROM billing_reconciliation_state WHERE tenant_id = $1 FOR UPDATE",
        )
        .bind(tenant_id.as_uuid())
        .fetch_one(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        if stored != provider.as_str() {
            return Err(BillingStoreError::ProviderMismatch);
        }
        Ok(())
    }

    async fn require_live_task(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
    ) -> Result<(), BillingStoreError> {
        let present: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM billing_reconciliation_tasks \
             WHERE id = $1 AND tenant_id = $2 AND provider = $3 AND status = 'processing' \
                AND lease_token = $4 AND lease_expires_at > clock_timestamp() \
             FOR UPDATE",
        )
        .bind(claim.id.as_uuid())
        .bind(claim.tenant_id.as_uuid())
        .bind(claim.provider.as_str())
        .bind(claim.lease_token)
        .fetch_optional(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        if present.is_some() {
            Ok(())
        } else {
            Err(BillingStoreError::LostLease)
        }
    }

    async fn replace_mirrors(
        &self,
        connection: &mut PgConnection,
        snapshot: &ProviderSnapshot,
    ) -> Result<(), BillingStoreError> {
        let customer_facts = serde_json::to_value(snapshot.customer().state())
            .map_err(|_| BillingStoreError::Encoding)?;
        sqlx::query(
            "INSERT INTO billing_customers ( \
                tenant_id, provider, provider_customer_id, provider_revision, state_facts, \
                reconciled_at, created_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
                provider_customer_id = EXCLUDED.provider_customer_id, \
                provider_revision = EXCLUDED.provider_revision, state_facts = EXCLUDED.state_facts, \
                reconciled_at = EXCLUDED.reconciled_at, updated_at = clock_timestamp() \
             WHERE billing_customers.provider = EXCLUDED.provider",
        )
        .bind(snapshot.tenant_id().as_uuid())
        .bind(snapshot.provider().as_str())
        .bind(snapshot.customer().id().as_str())
        .bind(snapshot.revision().get())
        .bind(customer_facts)
        .bind(snapshot.observed_at())
        .execute(&mut *connection)
        .await.map_err(map_sqlx)?;
        sqlx::query("DELETE FROM billing_subscriptions WHERE tenant_id = $1 AND provider = $2")
            .bind(snapshot.tenant_id().as_uuid())
            .bind(snapshot.provider().as_str())
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
        for subscription in snapshot.subscriptions() {
            let access = self.subscription_access(snapshot, subscription)?;
            let state = serde_json::to_value(subscription.state())
                .map_err(|_| BillingStoreError::Encoding)?;
            sqlx::query(
                "INSERT INTO billing_subscriptions ( \
                    tenant_id, provider, provider_subscription_id, provider_customer_id, \
                    provider_price_id, standing, access_state, current_period_end, grace_until, \
                    dunning_started_at, dunning_attempt_count, dunning_next_attempt_at, state_facts, \
                    provider_revision, reconciled_at, created_at, updated_at \
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                    clock_timestamp(), clock_timestamp())",
            )
            .bind(snapshot.tenant_id().as_uuid())
            .bind(snapshot.provider().as_str())
            .bind(subscription.id().as_str())
            .bind(subscription.customer_id().as_str())
            .bind(subscription.price_id().as_str())
            .bind(standing_name(subscription.standing()))
            .bind(access.state)
            .bind(subscription.current_period_end())
            .bind(access.grace_until)
            .bind(access.dunning_started_at)
            .bind(access.dunning_attempt_count)
            .bind(access.dunning_next_attempt_at)
            .bind(state)
            .bind(snapshot.revision().get())
            .bind(snapshot.observed_at())
            .execute(&mut *connection)
            .await.map_err(map_sqlx)?;
        }
        sqlx::query("DELETE FROM billing_invoices WHERE tenant_id = $1 AND provider = $2")
            .bind(snapshot.tenant_id().as_uuid())
            .bind(snapshot.provider().as_str())
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
        for invoice in snapshot.invoices() {
            let state =
                serde_json::to_value(invoice.state()).map_err(|_| BillingStoreError::Encoding)?;
            sqlx::query(
                "INSERT INTO billing_invoices ( \
                    tenant_id, provider, provider_invoice_id, provider_customer_id, \
                    amount_due_minor, currency, due_at, paid_at, state_facts, provider_revision, \
                    reconciled_at, created_at, updated_at \
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                    clock_timestamp(), clock_timestamp())",
            )
            .bind(snapshot.tenant_id().as_uuid())
            .bind(snapshot.provider().as_str())
            .bind(invoice.id().as_str())
            .bind(invoice.customer_id().as_str())
            .bind(
                i64::try_from(invoice.amount_due_minor())
                    .map_err(|_| BillingStoreError::InvalidValue)?,
            )
            .bind(invoice.currency().as_str())
            .bind(invoice.due_at())
            .bind(invoice.paid_at())
            .bind(state)
            .bind(snapshot.revision().get())
            .bind(snapshot.observed_at())
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
        }
        Ok(())
    }

    fn subscription_access(
        &self,
        snapshot: &ProviderSnapshot,
        subscription: &crate::ProviderSubscription,
    ) -> Result<SubscriptionAccess, BillingStoreError> {
        match subscription.standing() {
            BillingStanding::InGoodStanding => {
                if subscription.dunning().is_some() {
                    return Err(BillingStoreError::InvalidSnapshot);
                }
                Ok(SubscriptionAccess {
                    state: "active",
                    grace_until: None,
                    dunning_started_at: None,
                    dunning_attempt_count: None,
                    dunning_next_attempt_at: None,
                })
            }
            BillingStanding::Pending | BillingStanding::Ended => {
                if subscription.dunning().is_some() {
                    return Err(BillingStoreError::InvalidSnapshot);
                }
                Ok(SubscriptionAccess {
                    state: "denied",
                    grace_until: None,
                    dunning_started_at: None,
                    dunning_attempt_count: None,
                    dunning_next_attempt_at: None,
                })
            }
            BillingStanding::Delinquent => {
                let dunning = subscription
                    .dunning()
                    .ok_or(BillingStoreError::InvalidSnapshot)?;
                if dunning.started_at() > snapshot.observed_at() {
                    return Err(BillingStoreError::InvalidSnapshot);
                }
                let grace_micros = i64::try_from(self.config.delinquent_grace.as_micros())
                    .map_err(|_| BillingStoreError::InvalidConfiguration)?;
                let grace_until = dunning
                    .started_at()
                    .checked_add(time::Duration::microseconds(grace_micros))
                    .ok_or(BillingStoreError::InvalidSnapshot)?;
                let access = if grace_until > snapshot.observed_at() {
                    "grace"
                } else {
                    "denied"
                };
                Ok(SubscriptionAccess {
                    state: access,
                    grace_until: (access == "grace").then_some(grace_until),
                    dunning_started_at: Some(dunning.started_at()),
                    dunning_attempt_count: Some(i32::from(dunning.attempt_count())),
                    dunning_next_attempt_at: dunning.next_attempt_at(),
                })
            }
        }
    }

    async fn replace_effective_entitlements(
        &self,
        connection: &mut PgConnection,
        snapshot: &ProviderSnapshot,
    ) -> Result<u64, BillingStoreError> {
        sqlx::query("DELETE FROM billing_entitlements WHERE tenant_id = $1")
            .bind(snapshot.tenant_id().as_uuid())
            .execute(&mut *connection)
            .await
            .map_err(map_sqlx)?;
        let result = sqlx::query(
            "INSERT INTO billing_entitlements ( \
                tenant_id, entitlement_key, provider, value_kind, boolean_value, limit_value, \
                provider_revision, valid_until, in_grace, reconciled_at \
             ) \
             SELECT $1, grants.entitlement_key, $2, grants.value_kind, \
                CASE WHEN grants.value_kind = 'boolean' THEN bool_or(grants.boolean_value) END, \
                CASE WHEN grants.value_kind = 'limit' THEN max(grants.limit_value) END, \
                $3, CASE WHEN bool_or(CASE WHEN subscriptions.access_state = 'grace' \
                    THEN subscriptions.grace_until ELSE subscriptions.current_period_end END IS NULL) \
                    THEN NULL ELSE max(CASE WHEN subscriptions.access_state = 'grace' \
                    THEN subscriptions.grace_until ELSE subscriptions.current_period_end END) END, \
                bool_and(subscriptions.access_state = 'grace'), $4 \
             FROM billing_subscriptions AS subscriptions \
             JOIN billing_provider_prices AS prices \
                ON prices.provider = subscriptions.provider \
                AND prices.provider_price_id = subscriptions.provider_price_id \
             JOIN billing_plans AS plans ON plans.plan_key = prices.plan_key AND plans.enabled \
             JOIN billing_plan_entitlements AS grants ON grants.plan_key = plans.plan_key \
             WHERE subscriptions.tenant_id = $1 AND subscriptions.provider = $2 \
                AND subscriptions.access_state IN ('active', 'grace') \
             GROUP BY grants.entitlement_key, grants.value_kind",
        )
        .bind(snapshot.tenant_id().as_uuid())
        .bind(snapshot.provider().as_str())
        .bind(snapshot.revision().get())
        .bind(snapshot.observed_at())
        .execute(&mut *connection)
        .await.map_err(map_sqlx)?;
        let entitlement_count = result.rows_affected();
        if entitlement_count > MAX_EFFECTIVE_ENTITLEMENTS {
            return Err(BillingStoreError::InvalidSnapshot);
        }
        Ok(entitlement_count)
    }

    async fn complete_task(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
    ) -> Result<(), BillingStoreError> {
        let result = sqlx::query(
            "UPDATE billing_reconciliation_tasks SET status = 'completed', lease_token = NULL, \
                lease_expires_at = NULL, completed_at = clock_timestamp(), \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND lease_token = $2 AND status = 'processing' \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.id.as_uuid())
        .bind(claim.lease_token)
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        require_fence(result.rows_affected())
    }

    async fn dead_letter_in_transaction(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
        failure: &str,
    ) -> Result<(), BillingStoreError> {
        let result = sqlx::query(
            "UPDATE billing_reconciliation_tasks SET status = 'dead_letter', lease_token = NULL, \
                lease_expires_at = NULL, last_error_class = $3, \
                dead_lettered_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE id = $1 AND lease_token = $2 AND status = 'processing' \
                AND lease_expires_at > clock_timestamp()",
        )
        .bind(claim.id.as_uuid())
        .bind(claim.lease_token)
        .bind(failure)
        .execute(&mut *connection)
        .await
        .map_err(map_sqlx)?;
        require_fence(result.rows_affected())
    }

    async fn append_audit(
        &self,
        connection: &mut PgConnection,
        record: AuditRecord,
    ) -> Result<(), BillingStoreError> {
        let AuditRecord {
            actor,
            scope,
            event_type,
            action,
            resource_kind,
            resource_id,
            outcome,
        } = record;
        let mut builder = AuditEvent::builder(
            AuditEventType::new(event_type).map_err(|_| BillingStoreError::InvalidValue)?,
            OffsetDateTime::now_utc(),
            actor,
            scope,
            Action::new(action).map_err(|_| BillingStoreError::InvalidValue)?,
            ResourceKind::new(resource_kind).map_err(|_| BillingStoreError::InvalidValue)?,
            outcome,
        );
        if let Some(resource_id) = resource_id {
            builder = builder.resource_id(
                AuditResourceId::new(resource_id).map_err(|_| BillingStoreError::InvalidValue)?,
            );
        }
        match self.audit.append_with(connection, &builder.build()).await {
            Ok(AuditAppendOutcome::Appended) => Ok(()),
            Ok(AuditAppendOutcome::Disabled) | Err(_) => Err(BillingStoreError::Audit),
        }
    }

    async fn append_entitlements_event(
        &self,
        connection: &mut PgConnection,
        claim: &ClaimedReconciliation,
        revision: ProviderRevision,
        entitlement_count: u64,
        available_at: OffsetDateTime,
    ) -> Result<(), BillingStoreError> {
        let options = EventEnvelopeOptions::new(
            Source::try_from("billing").map_err(|_| BillingStoreError::Encoding)?,
            Subject::try_from("entitlements").map_err(|_| BillingStoreError::Encoding)?,
            claim.id.as_uuid(),
        )
        .map_err(|_| BillingStoreError::Encoding)?
        .with_tenant(
            JobTenantId::try_from(claim.tenant_id.to_string())
                .map_err(|_| BillingStoreError::Encoding)?,
        );
        let envelope = EventEnvelope::new(
            EntitlementsReconciled {
                tenant_id: claim.tenant_id,
                provider: claim.provider.clone(),
                provider_revision: revision.get(),
                entitlement_count,
            },
            options,
            EventLimits::default(),
        )
        .map_err(|_| BillingStoreError::Encoding)?;
        self.outbox
            .append(
                connection,
                &envelope,
                "billing_entitlements",
                &claim.tenant_id.to_string(),
                &Destination::try_from(OUTBOX_DESTINATION)
                    .map_err(|_| BillingStoreError::Encoding)?,
                available_at,
                EventLimits::default(),
            )
            .await
            .map_err(|_| BillingStoreError::Outbox)?;
        Ok(())
    }
}

impl fmt::Debug for PostgresBillingStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresBillingStore")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Display-safe billing persistence failure without provider payload or credential retention.
#[derive(Debug, Error)]
pub enum BillingStoreError {
    /// Billing is disabled or local execution bounds are invalid.
    #[error("billing configuration is invalid")]
    InvalidConfiguration,
    /// A bounded public value or encoded record was invalid.
    #[error("billing value is invalid")]
    InvalidValue,
    /// The provider supplied an internally incoherent snapshot.
    #[error("billing provider snapshot is invalid")]
    InvalidSnapshot,
    /// A tenant already belongs to another exact provider adapter.
    #[error("billing provider does not match tenant state")]
    ProviderMismatch,
    /// An identity or value kind was reused with different immutable facts.
    #[error("billing immutable identity conflicts with stored state")]
    Conflict,
    /// A PostgreSQL integrity constraint rejected the attempted persisted transition.
    #[error("billing database constraint rejected operation")]
    Constraint(#[source] sqlx::Error),
    /// The exact reconciliation lease expired or was replaced.
    #[error("billing reconciliation lease was lost")]
    LostLease,
    /// A requested durable record was absent within the tenant boundary.
    #[error("billing record was not found")]
    NotFound,
    /// Bounded JSON or canonical event encoding failed.
    #[error("billing encoding failed")]
    Encoding,
    /// Transactional audit append failed.
    #[error("billing audit append failed")]
    Audit,
    /// Transactional outbox append failed.
    #[error("billing outbox append failed")]
    Outbox,
    /// Persisted rows failed bounded decoding or violated an internal representation invariant.
    #[error("billing persisted state is invalid")]
    CorruptState,
    /// Managed PostgreSQL pool acquisition failed; display output does not expose the source.
    #[error("billing database connection failed")]
    Connection(#[source] PostgresError),
    /// PostgreSQL transaction or statement execution failed; display output hides the source.
    #[error("billing database operation failed")]
    Database(#[source] sqlx::Error),
}

fn claimed_from_row(
    id: ReconciliationTaskId,
    lease_token: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<ClaimedReconciliation, BillingStoreError> {
    let tenant_uuid: Uuid = row
        .try_get("tenant_id")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let tenant_id =
        TenantId::from_uuid(tenant_uuid).map_err(|_| BillingStoreError::CorruptState)?;
    let provider = ProviderId::parse(
        row.try_get::<String, _>("provider")
            .map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    let attempts: i32 = row
        .try_get("attempt_count")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let attempt_count = u16::try_from(attempts).map_err(|_| BillingStoreError::CorruptState)?;
    Ok(ClaimedReconciliation {
        id,
        tenant_id,
        provider,
        lease_token,
        lease_expires_at: row
            .try_get("lease_expires_at")
            .map_err(|_| BillingStoreError::CorruptState)?,
        attempt_count,
    })
}

fn claimed_usage_from_row(
    record_id: UsageRecordId,
    lease_token: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<ClaimedUsage, BillingStoreError> {
    let tenant_uuid: Uuid = row
        .try_get("tenant_id")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let tenant_id =
        TenantId::from_uuid(tenant_uuid).map_err(|_| BillingStoreError::CorruptState)?;
    let provider = ProviderId::parse(
        row.try_get::<String, _>("provider")
            .map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    let meter = MeterKey::parse(
        row.try_get::<String, _>("meter_key")
            .map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    let idempotency_key = UsageIdempotencyKey::parse(
        row.try_get::<String, _>("idempotency_key")
            .map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    let quantity: i64 = row
        .try_get("quantity")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let quantity = u64::try_from(quantity).map_err(|_| BillingStoreError::CorruptState)?;
    let attempts: i32 = row
        .try_get("attempt_count")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let attempt_count = u16::try_from(attempts).map_err(|_| BillingStoreError::CorruptState)?;
    Ok(ClaimedUsage {
        request: ProviderUsageRequest::restored(
            tenant_id,
            record_id,
            meter,
            idempotency_key,
            quantity,
            row.try_get("occurred_at")
                .map_err(|_| BillingStoreError::CorruptState)?,
        ),
        provider,
        lease_token,
        lease_expires_at: row
            .try_get("lease_expires_at")
            .map_err(|_| BillingStoreError::CorruptState)?,
        attempt_count,
    })
}

fn entitlement_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<EffectiveEntitlement, BillingStoreError> {
    let key = EntitlementKey::parse(
        row.try_get::<String, _>("entitlement_key")
            .map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    let kind: String = row
        .try_get("value_kind")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let value = match kind.as_str() {
        "boolean" => EntitlementValue::Boolean(
            row.try_get("boolean_value")
                .map_err(|_| BillingStoreError::CorruptState)?,
        ),
        "limit" => {
            let value: i64 = row
                .try_get("limit_value")
                .map_err(|_| BillingStoreError::CorruptState)?;
            EntitlementValue::Limit(
                u64::try_from(value).map_err(|_| BillingStoreError::CorruptState)?,
            )
        }
        _ => return Err(BillingStoreError::CorruptState),
    };
    let provider = ProviderId::parse(
        row.try_get::<String, _>("provider")
            .map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    let revision: i64 = row
        .try_get("provider_revision")
        .map_err(|_| BillingStoreError::CorruptState)?;
    let revision = ProviderRevision::new(
        u64::try_from(revision).map_err(|_| BillingStoreError::CorruptState)?,
    )
    .map_err(|_| BillingStoreError::CorruptState)?;
    Ok(EffectiveEntitlement::restored(
        key,
        value,
        provider,
        revision,
        row.try_get("valid_until")
            .map_err(|_| BillingStoreError::CorruptState)?,
        row.try_get("in_grace")
            .map_err(|_| BillingStoreError::CorruptState)?,
    ))
}

fn snapshot_fingerprint(snapshot: &ProviderSnapshot) -> Result<[u8; 32], BillingStoreError> {
    let mut digest = Sha256::new();
    digest.update(snapshot.tenant_id().as_uuid().as_bytes());
    digest.update(snapshot.provider().as_str().as_bytes());
    digest.update(snapshot.revision().get().to_be_bytes());
    update_encoded_digest(&mut digest, snapshot.customer())?;
    let mut subscriptions = snapshot.subscriptions().iter().collect::<Vec<_>>();
    subscriptions.sort_unstable_by(|left, right| left.id().cmp(right.id()));
    for subscription in subscriptions {
        update_encoded_digest(&mut digest, subscription)?;
    }
    let mut invoices = snapshot.invoices().iter().collect::<Vec<_>>();
    invoices.sort_unstable_by(|left, right| left.id().cmp(right.id()));
    for invoice in invoices {
        update_encoded_digest(&mut digest, invoice)?;
    }
    Ok(digest.finalize().into())
}

fn update_encoded_digest(
    digest: &mut Sha256,
    value: &impl Serialize,
) -> Result<(), BillingStoreError> {
    let encoded = serde_json::to_vec(value).map_err(|_| BillingStoreError::Encoding)?;
    digest.update(
        u64::try_from(encoded.len())
            .map_err(|_| BillingStoreError::Encoding)?
            .to_be_bytes(),
    );
    digest.update(encoded);
    Ok(())
}

fn usage_fingerprint(
    tenant_id: TenantId,
    provider: &ProviderId,
    usage: &NewUsageRecord,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(tenant_id.as_uuid().as_bytes());
    digest.update(provider.as_str().as_bytes());
    digest.update([0]);
    digest.update(usage.meter().as_str().as_bytes());
    digest.update([0]);
    digest.update(usage.idempotency_key().as_str().as_bytes());
    digest.update(usage.quantity().to_be_bytes());
    digest.update(usage.occurred_at().unix_timestamp_nanos().to_be_bytes());
    digest.finalize().into()
}

fn standing_name(standing: BillingStanding) -> &'static str {
    match standing {
        BillingStanding::InGoodStanding => "in_good_standing",
        BillingStanding::Delinquent => "delinquent",
        BillingStanding::Pending => "pending",
        BillingStanding::Ended => "ended",
    }
}

fn principal_actor(principal: &Principal) -> AuditActor {
    match principal.kind {
        PrincipalKind::User => AuditActor::User(principal.subject_id),
        PrincipalKind::ServiceAccount => AuditActor::ServiceAccount(principal.subject_id),
    }
}

fn duration_micros(duration: Duration) -> Result<i64, BillingStoreError> {
    i64::try_from(duration.as_micros()).map_err(|_| BillingStoreError::InvalidConfiguration)
}

fn safe_failure_class(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn require_fence(rows: u64) -> Result<(), BillingStoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(BillingStoreError::LostLease)
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
}

fn map_sqlx(error: sqlx::Error) -> BillingStoreError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| matches!(code.as_ref(), "23503" | "23505" | "23514"))
    {
        BillingStoreError::Constraint(error)
    } else {
        BillingStoreError::Database(error)
    }
}

impl From<BillingValueError> for BillingStoreError {
    fn from(_: BillingValueError) -> Self {
        Self::InvalidValue
    }
}
