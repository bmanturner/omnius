//! PostgreSQL contracts for durable notifications, preferences, digests, and unsubscribe.

use std::{error::Error, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsk_audit::{AuditConfig, PostgresAuditSink};
use rsk_auth_core::{SubjectId, TenantId};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_core::{CausationId, CorrelationId};
use rsk_email::{
    EmailAddress, EmailConfig, EmailService, EmailSubject, MailboxAddress, ProviderDeliveryEvent,
    ProviderDeliveryEventKind, ProviderMessageId, TemplateContext, TemplateName,
};
use rsk_jobs_core::{CapturingJobEnqueuer, DeliveryContext, HandlerOutcome, Job, TypedJobHandler};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_notifications::{
    AuthenticatedPreferenceChange, DedupeKey, DeliveryId, DeliveryMode, DeliveryStatus, DigestKey,
    DigestSpec, EmailPresentation, GeneratedUnsubscribeToken, Locale, NotificationChannel,
    NotificationClass, NotificationEmailHandler, NotificationEmailJob, NotificationError,
    NotificationOrchestrator, NotificationRequest, NotificationTemplate,
    OsUnsubscribeTokenGenerator, PreferenceCategory, PreferenceScope, PreferenceService,
    ProductEvent, ProviderEventOutcome, ProviderScope, TimeZone, UnsubscribeTarget,
    UnsubscribeToken, UnsubscribeTokenError, UnsubscribeTokenGenerator,
};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use serde_json::json;
use sqlx::Connection as _;
use sqlx::Row as _;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const NOTIFICATIONS_HEAD: i64 = 2_026_082_317;

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
    user: SubjectId,
    tenant: TenantId,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 3,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(5),
        application_name: "rsk-notifications-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(2),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

async fn database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, NOTIFICATIONS_HEAD)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(15),
        },
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    let user = SubjectId::new();
    let tenant = TenantId::new();
    let now = OffsetDateTime::now_utc();
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(user.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Notification tenant', 'active', 1, $2, $2, NULL)",
    )
    .bind(tenant.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, $3, $3)",
    )
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(TestDatabase {
        pool,
        fixture,
        user,
        tenant,
    })
}

fn request(
    database: &TestDatabase,
    dedupe: &str,
    classification: NotificationClass,
    mode: DeliveryMode,
) -> Result<NotificationRequest, Box<dyn Error>> {
    request_with_context(database, dedupe, classification, mode, "example")
}

fn request_with_context(
    database: &TestDatabase,
    dedupe: &str,
    classification: NotificationClass,
    mode: DeliveryMode,
    product: &str,
) -> Result<NotificationRequest, Box<dyn Error>> {
    let template = NotificationTemplate::new(TemplateName::try_from("notice")?, 3)?;
    let email = EmailPresentation::new(
        MailboxAddress::new(EmailAddress::try_from("recipient@example.test")?, None),
        MailboxAddress::new(EmailAddress::try_from("sender@example.test")?, None),
        EmailSubject::try_from("A notification")?,
        template,
        TemplateContext::new(json!({"product": product}))?,
    );
    Ok(NotificationRequest::new(
        database.tenant,
        database.user,
        ProductEvent::try_from("account.activity")?,
        vec![NotificationChannel::Email],
        classification,
        Locale::try_from("en-US")?,
        TimeZone::try_from("America/New_York")?,
        email,
        DedupeKey::try_from(dedupe)?,
        mode,
        CorrelationId::new(),
        Some(CausationId::new()),
    )?)
}

fn preference_service(
    pool: PostgresPool,
) -> Result<PreferenceService<OsUnsubscribeTokenGenerator>, NotificationError> {
    PreferenceService::new(
        rsk_notifications::PostgresNotificationRepository::new(pool),
        PostgresAuditSink::new(AuditConfig { enabled: true }),
        SecretString::from("notification-test-pepper-with-more-than-thirty-two-bytes".to_owned()),
    )
}

#[tokio::test]
async fn duplicate_schedule_is_one_exact_tenant_fenced_durable_job() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let intent = request(
        &database,
        "account-activity:one",
        NotificationClass::Optional(PreferenceCategory::try_from("product_updates")?),
        DeliveryMode::Immediate,
    )?;
    let first = orchestrator.schedule(&intent).await?;
    let second = orchestrator.schedule(&intent).await?;
    assert!(first.deliveries[0].inserted);
    assert!(!second.deliveries[0].inserted);
    assert_eq!(
        first.deliveries[0].delivery.id,
        second.deliveries[0].delivery.id
    );
    assert_eq!(queue.len()?, 1);
    let captured = queue.snapshot()?;
    assert_eq!(captured[0].job_name().as_str(), "notifications.send_email");
    assert_eq!(captured[0].version().get(), 1);
    assert!(captured[0].idempotency_key().is_some());
    let typed = captured[0].decode::<NotificationEmailJob>()?;
    assert_eq!(typed.payload().template().as_str(), "notice-v3");
    assert_eq!(typed.payload().template_version(), 3);
    assert_eq!(
        repository
            .get_delivery(TenantId::new(), first.deliveries[0].delivery.id)
            .await,
        Err(NotificationError::NotFound)
    );
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn optional_preference_suppresses_but_mandatory_delivery_bypasses_it()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let service = preference_service(database.pool.clone())?;
    let category = PreferenceCategory::try_from("product_updates")?;
    service
        .set_authenticated(&AuthenticatedPreferenceChange::new(
            database.user,
            PreferenceScope::Tenant(database.tenant),
            category.clone(),
            NotificationChannel::Email,
            false,
            CorrelationId::new(),
            None,
        ))
        .await?;
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let optional = request(
        &database,
        "preference:optional",
        NotificationClass::Optional(category),
        DeliveryMode::Immediate,
    )?;
    let scheduled = orchestrator.schedule(&optional).await?;
    let envelope = queue.drain()?.remove(0);
    let sender = email_service()?;
    let sink = sender.capturing_sink().ok_or("capturing sink missing")?;
    let handler = NotificationEmailHandler::new(
        repository.clone(),
        Arc::new(sender),
        ProviderScope::try_from("capturing-primary")?,
    );
    let typed = envelope.decode::<NotificationEmailJob>()?;
    let context = DeliveryContext::from_envelope(
        &envelope,
        1,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + time::Duration::seconds(20),
    )?;
    assert_eq!(
        handler.handle(typed.into_payload(), context).await,
        HandlerOutcome::Succeeded
    );
    assert_eq!(
        repository
            .get_delivery(database.tenant, scheduled.deliveries[0].delivery.id)
            .await?
            .status,
        DeliveryStatus::Suppressed
    );
    assert_eq!(sink.len()?, 0);

    let mandatory = request(
        &database,
        "preference:mandatory",
        NotificationClass::Mandatory,
        DeliveryMode::Immediate,
    )?;
    let scheduled = orchestrator.schedule(&mandatory).await?;
    let envelope = queue.drain()?.remove(0);
    let sender = email_service()?;
    let sink = sender.capturing_sink().ok_or("capturing sink missing")?;
    let handler = NotificationEmailHandler::new(
        repository.clone(),
        Arc::new(sender),
        ProviderScope::try_from("capturing-primary")?,
    );
    let typed = envelope.decode::<NotificationEmailJob>()?;
    let context = DeliveryContext::from_envelope(
        &envelope,
        1,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + time::Duration::seconds(20),
    )?;
    assert_eq!(
        handler.handle(typed.into_payload(), context).await,
        HandlerOutcome::Succeeded
    );
    assert_eq!(
        repository
            .get_delivery(database.tenant, scheduled.deliveries[0].delivery.id)
            .await?
            .status,
        DeliveryStatus::Accepted
    );
    assert_eq!(sink.len()?, 1);
    let captured = sink.snapshot()?;
    let rendered = captured[0].formatted_utf8()?;
    assert!(rendered.contains("Notification"));
    assert!(!rendered.contains("WRONG TEMPLATE VERSION"));
    database.fixture.cleanup().await?;
    Ok(())
}

fn email_service() -> Result<EmailService, Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!("rsk-notifications-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&root)?;
    let text = "{% if items is defined %}{{ items[0].product }} {{ items[1].product }}{% else %}Notification{% endif %}";
    let html = "<p>{% if items is defined %}{{ items[0].product }} {{ items[1].product }}{% else %}Notification{% endif %}</p>";
    std::fs::write(root.join("notice-v3.txt"), text)?;
    std::fs::write(root.join("notice-v3.html"), html)?;
    std::fs::write(root.join("notice-v4.txt"), "WRONG TEMPLATE VERSION")?;
    std::fs::write(root.join("notice-v4.html"), "<p>WRONG TEMPLATE VERSION</p>")?;
    let config: EmailConfig = serde_json::from_value(json!({
        "provider": {"provider": "capturing", "capacity": 8},
        "templates": {"directory": root, "allowed_templates": ["notice-v3", "notice-v4"]}
    }))?;
    Ok(EmailService::build(config, DeploymentEnvironment::Test)?)
}

#[derive(Clone, Copy, Debug)]
struct DeterministicGenerator(u8);
impl UnsubscribeTokenGenerator for DeterministicGenerator {
    fn generate(
        &self,
        pepper: &SecretString,
    ) -> Result<GeneratedUnsubscribeToken, UnsubscribeTokenError> {
        let token =
            UnsubscribeToken::parse(SecretString::from(URL_SAFE_NO_PAD.encode([self.0; 32])))?;
        let digest = token.digest(pepper)?;
        Ok(GeneratedUnsubscribeToken { token, digest })
    }
}

#[tokio::test]
async fn unsubscribe_is_scope_expiry_and_single_use_safe_with_atomic_audit()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let pepper =
        SecretString::from("notification-test-pepper-with-more-than-thirty-two-bytes".to_owned());
    let service = PreferenceService::with_generator(
        rsk_notifications::PostgresNotificationRepository::new(database.pool.clone()),
        PostgresAuditSink::new(AuditConfig { enabled: true }),
        pepper.clone(),
        DeterministicGenerator(7),
    )?;
    let target = UnsubscribeTarget::new(
        database.user,
        PreferenceScope::Tenant(database.tenant),
        PreferenceCategory::try_from("newsletter")?,
        NotificationChannel::Email,
    );
    let issued = service
        .issue_unsubscribe(
            database.user,
            &target,
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            CorrelationId::new(),
            None,
        )
        .await?;
    let wrong_scope = UnsubscribeTarget::new(
        database.user,
        PreferenceScope::Global,
        PreferenceCategory::try_from("newsletter")?,
        NotificationChannel::Email,
    );
    assert_eq!(
        service
            .unsubscribe_with_token(&issued.token, &wrong_scope, CorrelationId::new(), None)
            .await,
        Err(NotificationError::InvalidUnsubscribe)
    );
    let changed = service
        .unsubscribe_with_token(&issued.token, &target, CorrelationId::new(), None)
        .await?;
    assert!(!changed.enabled);
    assert_eq!(
        service
            .unsubscribe_with_token(&issued.token, &target, CorrelationId::new(), None)
            .await,
        Err(NotificationError::InvalidUnsubscribe)
    );

    let expired = UnsubscribeToken::parse(SecretString::from(URL_SAFE_NO_PAD.encode([8_u8; 32])))?;
    let expired_digest = expired.digest(&pepper)?;
    let now = OffsetDateTime::now_utc();
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "INSERT INTO notification_unsubscribe_tokens \
         (id, token_digest, purpose, recipient_id, scope, tenant_id, category, channel, issued_at, expires_at) \
         VALUES ($1,$2,'unsubscribe',$3,'tenant',$4,'newsletter','email',$5,$6)",
    )
    .bind(uuid::Uuid::now_v7()).bind(expired_digest.as_bytes().as_slice())
    .bind(database.user.as_uuid()).bind(database.tenant.as_uuid())
    .bind(now - time::Duration::hours(2)).bind(now - time::Duration::hours(1))
    .execute(&mut *connection).await?;
    assert_eq!(
        service
            .unsubscribe_with_token(&expired, &target, CorrelationId::new(), None)
            .await,
        Err(NotificationError::InvalidUnsubscribe)
    );
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type LIKE 'notification.%'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(audit_count, 2);
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn audit_failure_rolls_back_authenticated_preference() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let service = preference_service(database.pool.clone())?;
    let mut connection = database.pool.acquire().await?;
    sqlx::query("ALTER TABLE audit_events RENAME TO audit_events_unavailable")
        .execute(&mut *connection)
        .await?;
    let result = service
        .set_authenticated(&AuthenticatedPreferenceChange::new(
            database.user,
            PreferenceScope::Tenant(database.tenant),
            PreferenceCategory::try_from("rollback")?,
            NotificationChannel::Email,
            false,
            CorrelationId::new(),
            None,
        ))
        .await;
    assert_eq!(result, Err(NotificationError::AuditUnavailable));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_preferences WHERE recipient_id = $1 AND category = 'rollback'",
    ).bind(database.user.as_uuid()).fetch_one(&mut *connection).await?;
    assert_eq!(count, 0);
    sqlx::query("ALTER TABLE audit_events_unavailable RENAME TO audit_events")
        .execute(&mut *connection)
        .await?;
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn digest_assembles_distinct_members_once_and_never_dispatches_early()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let digest = DigestSpec::new(DigestKey::try_from("daily")?, Duration::from_secs(60))?;
    let first = request_with_context(
        &database,
        "digest:first",
        NotificationClass::Optional(PreferenceCategory::try_from("summary")?),
        DeliveryMode::Digest(digest.clone()),
        "first-member",
    )?;
    let second = request_with_context(
        &database,
        "digest:second",
        NotificationClass::Optional(PreferenceCategory::try_from("summary")?),
        DeliveryMode::Digest(digest),
        "second-member",
    )?;
    orchestrator.schedule(&first).await?;
    orchestrator.schedule(&second).await?;
    assert_eq!(queue.len()?, 0);
    assert_eq!(orchestrator.run_once(8).await?.accepted, 0);
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE notification_digest_buckets SET \
            bucket_started_at = bucket_started_at - interval '2 minutes', \
            bucket_ends_at = bucket_ends_at - interval '2 minutes'",
    )
    .execute(&mut *connection)
    .await?;
    assert_eq!(orchestrator.run_once(8).await?.accepted, 1);
    let envelope = queue.drain()?.remove(0);
    let sender = email_service()?;
    let sink = sender.capturing_sink().ok_or("capturing sink missing")?;
    let handler = NotificationEmailHandler::new(
        repository,
        Arc::new(sender),
        ProviderScope::try_from("capturing-primary")?,
    );
    let typed = envelope.decode::<NotificationEmailJob>()?;
    let context = DeliveryContext::from_envelope(
        &envelope,
        1,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + time::Duration::seconds(20),
    )?;
    assert_eq!(
        handler.handle(typed.into_payload(), context).await,
        HandlerOutcome::Succeeded
    );
    let rendered = sink.snapshot()?[0].formatted_utf8()?;
    assert!(rendered.contains("first-member"));
    assert!(rendered.contains("second-member"));
    let statuses: Vec<String> =
        sqlx::query("SELECT status FROM deliveries ORDER BY created_at, id")
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(|row| row.get("status"))
            .collect();
    assert_eq!(statuses, vec!["accepted", "coalesced"]);
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

async fn handle_envelope(
    repository: &rsk_notifications::PostgresNotificationRepository,
    envelope: &rsk_jobs_core::EncodedJobEnvelope,
    attempt: u16,
    cancellation: CancellationToken,
    deadline: OffsetDateTime,
    provider_scope: ProviderScope,
) -> Result<HandlerOutcome, Box<dyn Error>> {
    let sender = email_service()?;
    let handler =
        NotificationEmailHandler::new(repository.clone(), Arc::new(sender), provider_scope);
    let typed = envelope.decode::<NotificationEmailJob>()?;
    let context = DeliveryContext::from_envelope(envelope, attempt, cancellation, deadline)?;
    Ok(handler.handle(typed.into_payload(), context).await)
}

async fn assert_stale_envelope_rejected(
    repository: &rsk_notifications::PostgresNotificationRepository,
    envelope: &rsk_jobs_core::EncodedJobEnvelope,
) -> Result<(), Box<dyn Error>> {
    let sender = email_service()?;
    let sink = sender.capturing_sink().ok_or("capturing sink missing")?;
    let handler = NotificationEmailHandler::new(
        repository.clone(),
        Arc::new(sender),
        ProviderScope::try_from("capturing-primary")?,
    );
    let job = envelope.decode::<NotificationEmailJob>()?;
    let context = DeliveryContext::from_envelope(
        envelope,
        NotificationEmailJob::POLICY.max_attempts(),
        CancellationToken::new(),
        OffsetDateTime::now_utc() + time::Duration::seconds(20),
    )?;
    assert!(matches!(
        handler.handle(job.into_payload(), context).await,
        HandlerOutcome::Retryable(_)
    ));
    assert_eq!(sink.len()?, 0);
    Ok(())
}

async fn accepted_provider_delivery(
    database: &TestDatabase,
    repository: &rsk_notifications::PostgresNotificationRepository,
    orchestrator: &NotificationOrchestrator,
    queue: &CapturingJobEnqueuer,
    label: &str,
    provider_scope: ProviderScope,
) -> Result<(DeliveryId, ProviderMessageId), Box<dyn Error>> {
    let scheduled = orchestrator
        .schedule(&request(
            database,
            &format!("provider-event:{label}"),
            NotificationClass::Mandatory,
            DeliveryMode::Immediate,
        )?)
        .await?;
    let delivery_id = scheduled.deliveries[0].delivery.id;
    let envelope = queue.drain()?.remove(0);
    assert_eq!(
        handle_envelope(
            repository,
            &envelope,
            1,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(20),
            provider_scope,
        )
        .await?,
        HandlerOutcome::Succeeded
    );
    let mut connection = database.pool.acquire().await?;
    let provider_message_id: String = sqlx::query_scalar(
        "SELECT provider_message_id FROM deliveries WHERE tenant_id = $1 AND id = $2",
    )
    .bind(database.tenant.as_uuid())
    .bind(delivery_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    Ok((
        delivery_id,
        ProviderMessageId::try_from(provider_message_id)?,
    ))
}

#[tokio::test]
async fn terminal_provider_events_are_scoped_tenant_fenced_and_idempotent()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let cases = [
        (
            ProviderDeliveryEventKind::Delivered,
            DeliveryStatus::Delivered,
            "delivered",
        ),
        (
            ProviderDeliveryEventKind::Bounce {
                classification: rsk_email::ProviderBounceClass::Permanent,
            },
            DeliveryStatus::Bounced,
            "permanent-bounce",
        ),
        (
            ProviderDeliveryEventKind::Complaint,
            DeliveryStatus::Complained,
            "complaint",
        ),
    ];
    let mut first = None;
    let mut shared_provider_id = None;
    for (kind, expected, label) in cases {
        let scope = ProviderScope::try_from(format!("capturing-{label}"))?;
        let (_, provider_message_id) = accepted_provider_delivery(
            &database,
            &repository,
            &orchestrator,
            &queue,
            label,
            scope.clone(),
        )
        .await?;
        if let Some(shared) = shared_provider_id.as_ref() {
            assert_eq!(&provider_message_id, shared);
        } else {
            shared_provider_id = Some(provider_message_id.clone());
        }
        let event = ProviderDeliveryEvent::new(
            ProviderMessageId::try_from(format!("provider-event-{label}-1"))?,
            provider_message_id,
            i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)?,
            kind,
        );
        assert_eq!(
            repository
                .record_provider_event(database.tenant, &scope, &event)
                .await?,
            ProviderEventOutcome::Applied(expected)
        );
        assert_eq!(
            repository
                .record_provider_event(database.tenant, &scope, &event)
                .await?,
            ProviderEventOutcome::Duplicate(expected)
        );
        if first.is_none() {
            first = Some((scope, event));
        }
    }
    let (first_scope, first_event) = first.as_ref().ok_or("missing provider event")?;
    let conflict = ProviderDeliveryEvent::new(
        first_event.event_id().clone(),
        first_event.provider_message_id().clone(),
        first_event.occurred_at_unix_ms(),
        ProviderDeliveryEventKind::Complaint,
    );
    assert_eq!(
        repository
            .record_provider_event(database.tenant, first_scope, &conflict)
            .await,
        Err(NotificationError::InvalidState)
    );
    assert_eq!(
        repository
            .record_provider_event(TenantId::new(), first_scope, first_event)
            .await,
        Err(NotificationError::NotFound)
    );
    let mut connection = database.pool.acquire().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_provider_events WHERE tenant_id = $1",
    )
    .bind(database.tenant.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(count, 3);
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn nonterminal_bounces_allow_a_later_delivered_event() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let scope = ProviderScope::try_from("capturing-nonterminal")?;
    let (delivery_id, provider_message_id) = accepted_provider_delivery(
        &database,
        &repository,
        &orchestrator,
        &queue,
        "nonterminal-bounce",
        scope.clone(),
    )
    .await?;
    let occurred_at = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)?;
    for (event_id, classification) in [
        (
            "provider-event-transient-1",
            rsk_email::ProviderBounceClass::Transient,
        ),
        (
            "provider-event-undetermined-1",
            rsk_email::ProviderBounceClass::Undetermined,
        ),
    ] {
        let event = ProviderDeliveryEvent::new(
            ProviderMessageId::try_from(event_id)?,
            provider_message_id.clone(),
            occurred_at,
            ProviderDeliveryEventKind::Bounce { classification },
        );
        assert_eq!(
            repository
                .record_provider_event(database.tenant, &scope, &event)
                .await?,
            ProviderEventOutcome::Ignored(DeliveryStatus::Accepted)
        );
    }
    assert_eq!(
        repository
            .get_delivery(database.tenant, delivery_id)
            .await?
            .status,
        DeliveryStatus::Accepted
    );
    let delivered = ProviderDeliveryEvent::new(
        ProviderMessageId::try_from("provider-event-delivered-after-bounce")?,
        provider_message_id,
        occurred_at,
        ProviderDeliveryEventKind::Delivered,
    );
    assert_eq!(
        repository
            .record_provider_event(database.tenant, &scope, &delivered)
            .await?,
        ProviderEventOutcome::Applied(DeliveryStatus::Delivered)
    );
    let mut connection = database.pool.acquire().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_provider_events WHERE delivery_id = $1",
    )
    .bind(delivery_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(count, 3);
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn expired_final_claim_recovers_with_fresh_job_and_stale_fence_cannot_overwrite()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let scheduled = orchestrator
        .schedule(&request(
            &database,
            "send-lease:recovered",
            NotificationClass::Mandatory,
            DeliveryMode::Immediate,
        )?)
        .await?;
    let original = queue.drain()?.remove(0);
    let old_fence = uuid::Uuid::now_v7();
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE deliveries SET status = 'sending', attempt_count = 8, send_lease_token = $3, \
                send_lease_expires_at = clock_timestamp() - interval '1 second', \
                updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(database.tenant.as_uuid())
    .bind(scheduled.deliveries[0].delivery.id.as_uuid())
    .bind(old_fence)
    .execute(&mut *connection)
    .await?;
    assert_eq!(orchestrator.run_once(8).await?.accepted, 1);
    let recovered = queue.drain()?.remove(0);
    assert_ne!(recovered.id(), original.id());
    assert_eq!(recovered.idempotency_key(), original.idempotency_key());
    assert_eq!(
        recovered
            .decode::<NotificationEmailJob>()?
            .payload()
            .delivery_id(),
        original
            .decode::<NotificationEmailJob>()?
            .payload()
            .delivery_id()
    );
    assert_stale_envelope_rejected(&repository, &original).await?;
    assert_eq!(
        repository
            .get_delivery(database.tenant, scheduled.deliveries[0].delivery.id)
            .await?
            .status,
        DeliveryStatus::Queued
    );
    assert_eq!(
        handle_envelope(
            &repository,
            &recovered,
            1,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(20),
            ProviderScope::try_from("capturing-primary")?,
        )
        .await?,
        HandlerOutcome::Succeeded
    );
    let stale = sqlx::query(
        "UPDATE deliveries SET status = 'permanent_failed', final_at = clock_timestamp(), \
                send_lease_token = NULL, send_lease_expires_at = NULL \
         WHERE tenant_id = $1 AND id = $2 AND status = 'sending' AND send_lease_token = $3",
    )
    .bind(database.tenant.as_uuid())
    .bind(scheduled.deliveries[0].delivery.id.as_uuid())
    .bind(old_fence)
    .execute(&mut *connection)
    .await?;
    assert_eq!(stale.rows_affected(), 0);
    assert_eq!(
        repository
            .get_delivery(database.tenant, scheduled.deliveries[0].delivery.id)
            .await?
            .status,
        DeliveryStatus::Accepted
    );
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn interruption_requeues_but_persisted_cancellation_acknowledges_redelivery()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let scheduled = orchestrator
        .schedule(&request(
            &database,
            "redelivery:cancelled",
            NotificationClass::Mandatory,
            DeliveryMode::Immediate,
        )?)
        .await?;
    let envelope = queue.drain()?.remove(0);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        handle_envelope(
            &repository,
            &envelope,
            1,
            cancellation,
            OffsetDateTime::now_utc() + time::Duration::seconds(20),
            ProviderScope::try_from("capturing-primary")?,
        )
        .await?,
        HandlerOutcome::Cancelled
    );
    assert_eq!(
        repository
            .get_delivery(database.tenant, scheduled.deliveries[0].delivery.id)
            .await?
            .status,
        DeliveryStatus::Queued
    );
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE deliveries SET status = 'cancelled', final_at = clock_timestamp(), \
                updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2",
    )
    .bind(database.tenant.as_uuid())
    .bind(scheduled.deliveries[0].delivery.id.as_uuid())
    .execute(&mut *connection)
    .await?;
    assert_eq!(
        handle_envelope(
            &repository,
            &envelope,
            2,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(20),
            ProviderScope::try_from("capturing-primary")?,
        )
        .await?,
        HandlerOutcome::Succeeded
    );
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn final_deadline_failure_is_durably_retry_exhausted() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(8)?;
    let orchestrator = NotificationOrchestrator::new(repository.clone(), Arc::new(queue.clone()));
    let scheduled = orchestrator
        .schedule(&request(
            &database,
            "retry:exhausted",
            NotificationClass::Mandatory,
            DeliveryMode::Immediate,
        )?)
        .await?;
    let envelope = queue.drain()?.remove(0);
    assert!(matches!(
        handle_envelope(
            &repository,
            &envelope,
            NotificationEmailJob::POLICY.max_attempts(),
            CancellationToken::new(),
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
            ProviderScope::try_from("capturing-primary")?,
        )
        .await?,
        HandlerOutcome::Permanent(_)
    ));
    let mut connection = database.pool.acquire().await?;
    let row = sqlx::query(
        "SELECT status, last_failure_code FROM deliveries WHERE tenant_id = $1 AND id = $2",
    )
    .bind(database.tenant.as_uuid())
    .bind(scheduled.deliveries[0].delivery.id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.get::<String, _>("status"), "permanent_failed");
    assert_eq!(
        row.get::<String, _>("last_failure_code"),
        "notification_retry_exhausted"
    );
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn outbox_recovers_after_capacity_backoff_beyond_one_hundred_attempts()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let repository = rsk_notifications::PostgresNotificationRepository::new(database.pool.clone());
    let queue = CapturingJobEnqueuer::new(1)?;
    let orchestrator = NotificationOrchestrator::new(repository, Arc::new(queue.clone()));
    orchestrator
        .schedule(&request(
            &database,
            "outbox:occupy",
            NotificationClass::Mandatory,
            DeliveryMode::Immediate,
        )?)
        .await?;
    let deferred = orchestrator
        .schedule(&request(
            &database,
            "outbox:recover",
            NotificationClass::Mandatory,
            DeliveryMode::Immediate,
        )?)
        .await?;
    let deferred_id = deferred.deliveries[0].delivery.id;
    let mut connection = database.pool.acquire().await?;
    let backoff_seconds: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM available_at - clock_timestamp())::double precision \
         FROM notification_job_outbox WHERE delivery_id = $1",
    )
    .bind(deferred_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert!(backoff_seconds > 0.0);
    sqlx::query(
        "UPDATE notification_job_outbox SET dispatch_attempts = 100, \
                available_at = clock_timestamp() - interval '1 second' WHERE delivery_id = $1",
    )
    .bind(deferred_id.as_uuid())
    .execute(&mut *connection)
    .await?;
    assert_eq!(orchestrator.dispatch_pending(8).await?.deferred, 1);
    let row = sqlx::query(
        "SELECT dispatch_attempts, \
                EXTRACT(EPOCH FROM available_at - clock_timestamp())::double precision AS delay \
         FROM notification_job_outbox WHERE delivery_id = $1",
    )
    .bind(deferred_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.get::<i32, _>("dispatch_attempts"), 101);
    let delay = row.get::<f64, _>("delay");
    assert!(delay > 0.0 && delay <= 300.0);
    let _ = queue.drain()?;
    sqlx::query(
        "UPDATE notification_job_outbox SET available_at = clock_timestamp() - interval '1 second' \
         WHERE delivery_id = $1",
    )
    .bind(deferred_id.as_uuid())
    .execute(&mut *connection)
    .await?;
    assert_eq!(orchestrator.dispatch_pending(8).await?.accepted, 1);
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}
