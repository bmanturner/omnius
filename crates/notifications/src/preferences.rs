use std::fmt;

use metrics::counter;
use rsk_audit::{
    AuditActor, AuditAppendOutcome, AuditEvent, AuditEventType, AuditOutcome, AuditResourceId,
    AuditScope, PostgresAuditSink,
};
use rsk_auth_core::{SubjectId, TenantId};
use rsk_authz_basic::{Action, ResourceKind};
use rsk_config::SecretString;
use rsk_core::{CausationId, CorrelationId};
use sqlx::{Connection as _, Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    NotificationChannel, NotificationError, OsUnsubscribeTokenGenerator,
    PostgresNotificationRepository, PreferenceCategory, PreferenceScope, UnsubscribeToken,
    UnsubscribeTokenGenerator, error::map_sqlx,
};

const MAX_TOKEN_LIFETIME: time::Duration = time::Duration::days(30);

/// Authenticated self-service optional preference change.
#[derive(Clone, Debug)]
pub struct AuthenticatedPreferenceChange {
    actor: SubjectId,
    scope: PreferenceScope,
    category: PreferenceCategory,
    channel: NotificationChannel,
    enabled: bool,
    correlation_id: CorrelationId,
    causation_id: Option<CausationId>,
}

impl AuthenticatedPreferenceChange {
    /// Creates a self-only preference mutation. The actor is always the affected recipient.
    #[must_use]
    pub const fn new(
        actor: SubjectId,
        scope: PreferenceScope,
        category: PreferenceCategory,
        channel: NotificationChannel,
        enabled: bool,
        correlation_id: CorrelationId,
        causation_id: Option<CausationId>,
    ) -> Self {
        Self {
            actor,
            scope,
            category,
            channel,
            enabled,
            correlation_id,
            causation_id,
        }
    }
}

/// Exact scope bound into an unsubscribe capability.
#[derive(Clone, Debug)]
pub struct UnsubscribeTarget {
    recipient_id: SubjectId,
    scope: PreferenceScope,
    category: PreferenceCategory,
    channel: NotificationChannel,
}

impl UnsubscribeTarget {
    /// Creates an optional-category capability target.
    #[must_use]
    pub const fn new(
        recipient_id: SubjectId,
        scope: PreferenceScope,
        category: PreferenceCategory,
        channel: NotificationChannel,
    ) -> Self {
        Self {
            recipient_id,
            scope,
            category,
            channel,
        }
    }

    /// Affected recipient.
    #[must_use]
    pub const fn recipient_id(&self) -> SubjectId {
        self.recipient_id
    }

    /// Global or tenant scope.
    #[must_use]
    pub const fn scope(&self) -> PreferenceScope {
        self.scope
    }

    /// Optional category.
    #[must_use]
    pub const fn category(&self) -> &PreferenceCategory {
        &self.category
    }

    /// Exact channel.
    #[must_use]
    pub const fn channel(&self) -> NotificationChannel {
        self.channel
    }
}

/// Result of an atomic preference mutation and audit append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreferenceChangeOutcome {
    /// Stable non-secret preference row identity.
    pub preference_id: Uuid,
    /// New optional-category setting.
    pub enabled: bool,
    /// Database-authoritative mutation instant.
    pub updated_at: OffsetDateTime,
}

/// One post-commit unsubscribe presentation.
#[derive(Debug)]
pub struct IssuedUnsubscribe {
    /// Opaque bearer returned exactly once.
    pub token: UnsubscribeToken,
    /// Capability expiry.
    pub expires_at: OffsetDateTime,
}

/// Atomic, audited optional preference and unsubscribe lifecycle.
pub struct PreferenceService<G = OsUnsubscribeTokenGenerator> {
    repository: PostgresNotificationRepository,
    audit: PostgresAuditSink,
    pepper: SecretString,
    generator: G,
}

impl PreferenceService<OsUnsubscribeTokenGenerator> {
    /// Creates a service using OS CSPRNG token generation.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::AuditRequired`] when audit persistence is disabled.
    pub fn new(
        repository: PostgresNotificationRepository,
        audit: PostgresAuditSink,
        pepper: SecretString,
    ) -> Result<Self, NotificationError> {
        Self::with_generator(repository, audit, pepper, OsUnsubscribeTokenGenerator)
    }
}

impl<G: UnsubscribeTokenGenerator> PreferenceService<G> {
    /// Creates a service with an injectable generator for deterministic contract tests.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::AuditRequired`] when audit persistence is disabled.
    pub fn with_generator(
        repository: PostgresNotificationRepository,
        audit: PostgresAuditSink,
        pepper: SecretString,
        generator: G,
    ) -> Result<Self, NotificationError> {
        if !audit.config().enabled {
            return Err(NotificationError::AuditRequired);
        }
        Ok(Self {
            repository,
            audit,
            pepper,
            generator,
        })
    }

    /// Changes the authenticated actor's own optional category and appends audit in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError`] when work IDs are invalid or the atomic preference/audit
    /// transaction cannot complete.
    pub async fn set_authenticated(
        &self,
        change: &AuthenticatedPreferenceChange,
    ) -> Result<PreferenceChangeOutcome, NotificationError> {
        validate_work_ids(change.correlation_id, change.causation_id)?;
        let mut connection = self.repository.pool().acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let outcome = upsert_preference(
            &mut transaction,
            change.actor,
            change.scope,
            &change.category,
            change.channel,
            change.enabled,
        )
        .await?;
        let event = preference_audit_event(
            "notification.preference.changed",
            outcome.preference_id,
            "notifications.preference.set",
            PreferenceAuditContext {
                actor: AuditActor::User(change.actor),
                subject_id: change.actor,
                scope: change.scope,
                correlation_id: change.correlation_id,
                causation_id: change.causation_id,
            },
        )?;
        require_audit(self.audit.append_with(&mut transaction, &event).await?)?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        counter!("rsk_notifications_preference_total", "method" => "authenticated", "result" => "changed").increment(1);
        Ok(outcome)
    }

    /// Issues a self-scoped, single-purpose, expiring capability and audits the token record atomically.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::InvalidUnsubscribe`] when the actor, target, or expiry is
    /// invalid, or another [`NotificationError`] when token generation or atomic persistence fails.
    pub async fn issue_unsubscribe(
        &self,
        actor: SubjectId,
        target: &UnsubscribeTarget,
        expires_at: OffsetDateTime,
        correlation_id: CorrelationId,
        causation_id: Option<CausationId>,
    ) -> Result<IssuedUnsubscribe, NotificationError> {
        if actor != target.recipient_id {
            return Err(NotificationError::InvalidUnsubscribe);
        }
        validate_work_ids(correlation_id, causation_id)?;
        let generated = self.generator.generate(&self.pepper)?;
        let mut connection = self.repository.pool().acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| map_sqlx(&error))?;
        if expires_at <= now || expires_at > now + MAX_TOKEN_LIFETIME {
            return Err(NotificationError::InvalidUnsubscribe);
        }
        let token_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO notification_unsubscribe_tokens ( \
                id, token_digest, purpose, recipient_id, scope, tenant_id, category, channel, \
                issued_at, expires_at \
             ) VALUES ($1,$2,'unsubscribe',$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(token_id)
        .bind(generated.digest.as_bytes().as_slice())
        .bind(target.recipient_id.as_uuid())
        .bind(target.scope.as_str())
        .bind(target.scope.tenant_id().map(TenantId::as_uuid))
        .bind(target.category.as_str())
        .bind(target.channel.as_str())
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
        let event = preference_audit_event(
            "notification.unsubscribe.issued",
            token_id,
            "notifications.unsubscribe.issue",
            PreferenceAuditContext {
                actor: AuditActor::User(actor),
                subject_id: target.recipient_id,
                scope: target.scope,
                correlation_id,
                causation_id,
            },
        )?;
        require_audit(self.audit.append_with(&mut transaction, &event).await?)?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        counter!("rsk_notifications_unsubscribe_total", "operation" => "issue", "result" => "succeeded").increment(1);
        Ok(IssuedUnsubscribe {
            token: generated.token,
            expires_at,
        })
    }

    /// Atomically consumes an exact-scope capability, disables only that optional category, and audits.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::InvalidUnsubscribe`] for malformed, mismatched, expired,
    /// revoked, or consumed capabilities, or another [`NotificationError`] when the atomic
    /// preference/token/audit transaction fails.
    pub async fn unsubscribe_with_token(
        &self,
        token: &UnsubscribeToken,
        target: &UnsubscribeTarget,
        correlation_id: CorrelationId,
        causation_id: Option<CausationId>,
    ) -> Result<PreferenceChangeOutcome, NotificationError> {
        validate_work_ids(correlation_id, causation_id)?;
        let digest = token.digest(&self.pepper)?;
        let mut connection = self.repository.pool().acquire().await?;
        let mut transaction = connection.begin().await.map_err(|error| map_sqlx(&error))?;
        let token_row = sqlx::query(
            "SELECT id FROM notification_unsubscribe_tokens \
             WHERE token_digest = $1 AND purpose = 'unsubscribe' AND recipient_id = $2 \
               AND scope = $3 AND tenant_id IS NOT DISTINCT FROM $4 AND category = $5 \
               AND channel = $6 AND consumed_at IS NULL AND revoked_at IS NULL \
               AND expires_at > clock_timestamp() \
             FOR UPDATE",
        )
        .bind(digest.as_bytes().as_slice())
        .bind(target.recipient_id.as_uuid())
        .bind(target.scope.as_str())
        .bind(target.scope.tenant_id().map(TenantId::as_uuid))
        .bind(target.category.as_str())
        .bind(target.channel.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?
        .ok_or(NotificationError::InvalidUnsubscribe)?;
        let token_id: Uuid = token_row
            .try_get("id")
            .map_err(|_| NotificationError::InvalidState)?;
        let outcome = upsert_preference(
            &mut transaction,
            target.recipient_id,
            target.scope,
            &target.category,
            target.channel,
            false,
        )
        .await?;
        let consumed = sqlx::query(
            "UPDATE notification_unsubscribe_tokens SET consumed_at = clock_timestamp() \
             WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL \
               AND expires_at > clock_timestamp()",
        )
        .bind(token_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_sqlx(&error))?;
        if consumed.rows_affected() != 1 {
            return Err(NotificationError::InvalidUnsubscribe);
        }
        let event = preference_audit_event(
            "notification.unsubscribe.consumed",
            outcome.preference_id,
            "notifications.unsubscribe.consume",
            PreferenceAuditContext {
                actor: AuditActor::Anonymous,
                subject_id: target.recipient_id,
                scope: target.scope,
                correlation_id,
                causation_id,
            },
        )?;
        require_audit(self.audit.append_with(&mut transaction, &event).await?)?;
        transaction
            .commit()
            .await
            .map_err(|error| map_sqlx(&error))?;
        counter!("rsk_notifications_unsubscribe_total", "operation" => "consume", "result" => "succeeded").increment(1);
        Ok(outcome)
    }
}

impl<G> fmt::Debug for PreferenceService<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreferenceService")
            .field("repository", &self.repository)
            .field("audit", &self.audit)
            .field("pepper", &"[REDACTED]")
            .field("generator", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

async fn upsert_preference(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: SubjectId,
    scope: PreferenceScope,
    category: &PreferenceCategory,
    channel: NotificationChannel,
    enabled: bool,
) -> Result<PreferenceChangeOutcome, NotificationError> {
    let row = sqlx::query(
        "INSERT INTO notification_preferences ( \
            id, recipient_id, scope, tenant_id, category, channel, enabled, created_at, updated_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp(),clock_timestamp()) \
         ON CONFLICT (recipient_id, tenant_id, category, channel) \
         DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = clock_timestamp() \
         RETURNING id, enabled, updated_at",
    )
    .bind(Uuid::now_v7())
    .bind(recipient_id.as_uuid())
    .bind(scope.as_str())
    .bind(scope.tenant_id().map(TenantId::as_uuid))
    .bind(category.as_str())
    .bind(channel.as_str())
    .bind(enabled)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx(&error))?;
    Ok(PreferenceChangeOutcome {
        preference_id: row
            .try_get("id")
            .map_err(|_| NotificationError::InvalidState)?,
        enabled: row
            .try_get("enabled")
            .map_err(|_| NotificationError::InvalidState)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| NotificationError::InvalidState)?,
    })
}

#[derive(Clone, Copy)]
struct PreferenceAuditContext {
    actor: AuditActor,
    subject_id: SubjectId,
    scope: PreferenceScope,
    correlation_id: CorrelationId,
    causation_id: Option<CausationId>,
}

fn preference_audit_event(
    event_type: &'static str,
    resource_id: Uuid,
    action: &'static str,
    context: PreferenceAuditContext,
) -> Result<AuditEvent, NotificationError> {
    let event_type =
        AuditEventType::new(event_type).map_err(|_| NotificationError::InvalidState)?;
    let action = Action::new(action).map_err(|_| NotificationError::InvalidState)?;
    let resource = ResourceKind::new("notification_preference")
        .map_err(|_| NotificationError::InvalidState)?;
    let resource_id = AuditResourceId::new(resource_id.to_string())
        .map_err(|_| NotificationError::InvalidState)?;
    let audit_scope = match context.scope {
        PreferenceScope::Global => AuditScope::Global,
        PreferenceScope::Tenant(tenant_id) => AuditScope::Tenant(tenant_id),
    };
    let mut builder = AuditEvent::builder(
        event_type,
        OffsetDateTime::now_utc(),
        context.actor,
        audit_scope,
        action,
        resource,
        AuditOutcome::Succeeded,
    )
    .subject_id(context.subject_id)
    .resource_id(resource_id)
    .correlation_id(context.correlation_id);
    if let Some(causation_id) = context.causation_id {
        builder = builder.causation_id(causation_id);
    }
    Ok(builder.build())
}

fn require_audit(outcome: AuditAppendOutcome) -> Result<(), NotificationError> {
    match outcome {
        AuditAppendOutcome::Appended => Ok(()),
        AuditAppendOutcome::Disabled => Err(NotificationError::AuditRequired),
    }
}

fn validate_work_ids(
    correlation_id: CorrelationId,
    causation_id: Option<CausationId>,
) -> Result<(), NotificationError> {
    if !correlation_id.is_v7() || causation_id.is_some_and(|value| !value.is_v7()) {
        return Err(NotificationError::InvalidRequest);
    }
    Ok(())
}
