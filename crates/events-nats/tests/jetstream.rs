//! Real `JetStream` provisioning, recovery, DLQ, drain, and least-privilege contracts.

use std::{
    collections::BTreeMap,
    error::Error,
    future::Future,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_nats::jetstream::{self, AckKind, message::PublishMessage};
use bytes::Bytes;
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_events_nats::{
    DeliveryContext, EventHandler, HandlerOutcome, NatsAuthConfig, NatsConnectionConfig,
    NatsConsumerConfig, NatsDeliveryConfig, NatsDiscardPolicy, NatsDlqConfig, NatsEventsConfig,
    NatsEventsError, NatsJetStreamEvents, NatsJetStreamProvisioner, NatsOutboxPublisher,
    NatsRestartConfig, NatsRetentionPolicy, NatsStorage, NatsStreamConfig, RawEvent,
};
use omnius_jobs_core::{
    Destination, DomainEvent, EventEnvelope, EventEnvelopeOptions, EventLimits, FailureCode,
    Source, Subject,
};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_outbox::{OutboxConfig, OutboxPublisher as _, PostgresOutbox};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_runtime::Supervisor;
use omnius_test_support::{NatsFixture, NatsRoleFixture, PostgresFixture};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Connection as _;
use time::OffsetDateTime;
use tokio::{sync::Notify, time as tokio_time};
use url::Url;

const SCHEMA_HEAD: i64 = 2_026_082_314;
const DESTINATION: &str = "nats:test-events";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestEvent {
    sequence: u32,
}

impl DomainEvent for TestEvent {
    const NAME: &'static str = "test.created.v1";
    const VERSION: u16 = 1;
}

fn event_envelope(sequence: u32) -> TestResult<EventEnvelope<TestEvent>> {
    Ok(EventEnvelope::new(
        TestEvent { sequence },
        EventEnvelopeOptions::new(
            Source::try_from("events-nats-test")?,
            Subject::try_from(format!("test/{sequence}"))?,
            uuid::Uuid::now_v7(),
        )?,
        EventLimits::default(),
    )?)
}

fn raw_event(sequence: u32) -> TestResult<(RawEvent, Value)> {
    let envelope = event_envelope(sequence)?;
    let bytes = envelope.encode(EventLimits::default())?;
    let value = serde_json::from_slice(&bytes)?;
    Ok((RawEvent::decode(Bytes::from(bytes), 512 * 1024)?, value))
}

fn events_config(
    stream_name: &str,
    dlq_stream_name: &str,
    durable_name: &str,
    prefix: &str,
) -> NatsEventsConfig {
    let event_filter = format!("{prefix}.events.>");
    let event_subject = format!("{prefix}.events.test");
    let dlq_subject = format!("{prefix}.dlq");
    let stream = NatsStreamConfig {
        name: stream_name.to_owned(),
        subjects: vec![event_filter.clone()],
        retention: NatsRetentionPolicy::Limits,
        storage: NatsStorage::Memory,
        discard: NatsDiscardPolicy::Old,
        replicas: 1,
        max_age: Duration::from_hours(1),
        max_bytes: 32 * 1024 * 1024,
        max_messages: 10_000,
        max_message_size: 512 * 1024,
        max_consumers: 16,
        duplicate_window: Duration::from_mins(5),
    };
    NatsEventsConfig {
        stream,
        routes: BTreeMap::from([(DESTINATION.to_owned(), event_subject)]),
        consumer: NatsConsumerConfig {
            durable_name: durable_name.to_owned(),
            filter_subjects: vec![event_filter],
            ack_wait: Duration::from_millis(500),
            max_deliveries: 3,
            max_ack_pending: 16,
        },
        delivery: NatsDeliveryConfig {
            pull_batch: 8,
            pull_max_bytes: 4 * 1024 * 1024,
            concurrency: 4,
            pull_expiry: Duration::from_millis(500),
            handler_timeout: Duration::from_millis(250),
            retry_nak_delay: Duration::from_millis(50),
            shutdown_timeout: Duration::from_secs(2),
        },
        dlq: NatsDlqConfig {
            stream: NatsStreamConfig {
                name: dlq_stream_name.to_owned(),
                subjects: vec![dlq_subject.clone()],
                retention: NatsRetentionPolicy::Limits,
                storage: NatsStorage::Memory,
                discard: NatsDiscardPolicy::Old,
                replicas: 1,
                max_age: Duration::from_hours(24),
                max_bytes: 32 * 1024 * 1024,
                max_messages: 10_000,
                max_message_size: 513 * 1024,
                max_consumers: 16,
                duplicate_window: Duration::from_mins(5),
            },
            subject: dlq_subject,
        },
        restart: NatsRestartConfig {
            max_restarts: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            jitter_percent: 0,
        },
        heartbeat_stale_after: Duration::from_secs(1),
        health_timeout: Duration::from_millis(500),
    }
}

fn fixture_names(fixture: &NatsFixture) -> (String, String, String) {
    let suffix = fixture
        .subject_prefix()
        .replace('.', "_")
        .to_ascii_uppercase();
    (
        format!("{suffix}_EVENTS"),
        format!("{suffix}_DLQ"),
        format!("{suffix}_WORKER"),
    )
}

fn connection_config(url: &SecretString) -> TestResult<NatsConnectionConfig> {
    let mut parsed = Url::parse(url.expose_secret())?;
    let username = parsed.username().to_owned();
    let password = parsed
        .password()
        .ok_or_else(|| io::Error::other("fixture URL has no password"))?
        .to_owned();
    parsed
        .set_username("")
        .map_err(|()| io::Error::other("fixture URL username could not be removed"))?;
    parsed
        .set_password(None)
        .map_err(|()| io::Error::other("fixture URL password could not be removed"))?;
    let mut config = NatsConnectionConfig::new(
        SecretString::from(parsed.to_string()),
        NatsAuthConfig::UserPassword {
            username: SecretString::from(username),
            password: SecretString::from(password),
        },
    );
    config.tls_required = false;
    config.operation_timeout = Duration::from_secs(2);
    config.connection_timeout = Duration::from_secs(2);
    Ok(config)
}

async fn sdk_connect(url: &SecretString) -> TestResult<async_nats::Client> {
    let parsed = Url::parse(url.expose_secret())?;
    let username = parsed.username().to_owned();
    let password = parsed
        .password()
        .ok_or_else(|| io::Error::other("fixture URL has no password"))?
        .to_owned();
    Ok(
        async_nats::ConnectOptions::with_user_and_password(username, password)
            .connection_timeout(Duration::from_secs(2))
            .request_timeout(Some(Duration::from_secs(2)))
            .connect(url.expose_secret())
            .await?,
    )
}

async fn provision(
    url: &SecretString,
    config: NatsEventsConfig,
) -> TestResult<omnius_events_nats::ProvisioningReport> {
    Ok(NatsJetStreamProvisioner::connect(
        &connection_config(url)?,
        config,
        DeploymentEnvironment::Test,
    )
    .await?
    .provision()
    .await?)
}

async fn publish_raw(
    url: &SecretString,
    config: &NatsEventsConfig,
    event: &RawEvent,
) -> TestResult {
    publish_bytes(url, config, event.canonical_bytes(), event.id().to_string()).await
}

async fn publish_bytes(
    url: &SecretString,
    config: &NatsEventsConfig,
    bytes: &[u8],
    message_id: String,
) -> TestResult {
    let client = sdk_connect(url).await?;
    let context = jetstream::new(client.clone());
    let subject = config
        .routes
        .get(DESTINATION)
        .ok_or_else(|| io::Error::other("test destination missing"))?
        .clone();
    let ack = context
        .send_publish(
            subject,
            PublishMessage::build()
                .payload(Bytes::copy_from_slice(bytes))
                .message_id(message_id),
        )
        .await?
        .await?;
    if ack.stream != config.stream.name {
        return Err(io::Error::other("publish acknowledgement stream mismatch").into());
    }
    client.flush().await?;
    Ok(())
}

async fn wait_until<F, Fut>(mut predicate: F) -> TestResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = TestResult<bool>>,
{
    tokio_time::timeout(Duration::from_secs(8), async {
        loop {
            if predicate().await? {
                return TestResult::Ok(());
            }
            tokio_time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    Ok(())
}

#[test]
fn configuration_and_errors_are_bounded_and_redacted() -> TestResult {
    let secret = "nats://top-secret-user:top-secret-password@127.0.0.1:4222";
    let connection = connection_config(&SecretString::from(secret.to_owned()))?;
    let config = events_config(
        "PRIVATE_EVENTS",
        "PRIVATE_DLQ",
        "PRIVATE_WORKER",
        "private.subject",
    );
    config.validate_for(DeploymentEnvironment::Test)?;
    let debug = format!("{connection:?} {config:?}");
    assert!(!debug.contains("top-secret"));
    assert!(!debug.contains("private.subject"));
    assert!(!debug.contains("PRIVATE_EVENTS"));

    let mut invalid = config.clone();
    invalid.delivery.pull_batch = invalid.consumer.max_ack_pending + 1;
    assert!(matches!(
        invalid.validate_for(DeploymentEnvironment::Test),
        Err(error) if !error.to_string().contains("private")
    ));

    let mut production = connection;
    production.tls_required = false;
    assert!(matches!(
        production.validate_for(DeploymentEnvironment::Production),
        Err(error) if !error.to_string().contains("top-secret")
    ));
    Ok(())
}

#[tokio::test]
async fn provisioning_is_explicit_idempotent_and_runtime_rejects_drift() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    let missing = NatsJetStreamEvents::connect(
        &connection_config(fixture.nats_url())?,
        config.clone(),
        DeploymentEnvironment::Test,
    )
    .await;
    assert!(matches!(missing, Err(NatsEventsError::Access)));
    let untouched = jetstream::new(sdk_connect(fixture.nats_url()).await?)
        .get_stream(&stream)
        .await;
    assert!(untouched.is_err());
    let first = provision(fixture.nats_url(), config.clone()).await?;
    assert!(first.changed());
    let second = provision(fixture.nats_url(), config.clone()).await?;
    assert!(!second.changed());

    let client = sdk_connect(fixture.nats_url()).await?;
    let context = jetstream::new(client);
    let mut actual = context.get_stream(&stream).await?.get_info().await?.config;
    actual.max_messages += 1;
    context.update_stream(actual).await?;
    let unsafe_update = NatsJetStreamProvisioner::connect(
        &connection_config(fixture.nats_url())?,
        config.clone(),
        DeploymentEnvironment::Test,
    )
    .await?
    .provision()
    .await;
    assert!(matches!(unsafe_update, Err(NatsEventsError::UnsafeDrift)));
    let runtime = NatsJetStreamEvents::connect(
        &connection_config(fixture.nats_url())?,
        config,
        DeploymentEnvironment::Test,
    )
    .await;
    assert!(matches!(runtime, Err(NatsEventsError::Drift)));
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn role_credentials_prove_runtime_admin_and_subject_denial() -> TestResult {
    let fixture = NatsRoleFixture::start().await?;
    let config = events_config(
        fixture.stream_name(),
        fixture.dlq_stream_name(),
        fixture.durable_name(),
        fixture.subject_prefix(),
    );
    provision(fixture.admin_url(), config.clone()).await?;
    NatsOutboxPublisher::connect(
        &connection_config(fixture.publisher_url())?,
        &config,
        DeploymentEnvironment::Test,
    )
    .await?;
    NatsJetStreamEvents::connect(
        &connection_config(fixture.consumer_url())?,
        config.clone(),
        DeploymentEnvironment::Test,
    )
    .await?;

    let consumer_client = sdk_connect(fixture.consumer_url()).await?;
    let consumer_context = jetstream::new(consumer_client);
    let event_subject = config
        .routes
        .get(DESTINATION)
        .ok_or_else(|| io::Error::other("test destination missing"))?
        .clone();
    let subject_denied = match consumer_context
        .publish(event_subject, Bytes::from_static(b"denied"))
        .await
    {
        Ok(ack) => ack.await.is_err(),
        Err(_) => true,
    };
    assert!(subject_denied);
    let mut stream_config = consumer_context
        .get_stream(fixture.stream_name())
        .await?
        .get_info()
        .await?
        .config;
    stream_config.max_messages += 1;
    assert!(consumer_context.update_stream(stream_config).await.is_err());

    let publisher_client = sdk_connect(fixture.publisher_url()).await?;
    let publisher_context = jetstream::new(publisher_client);
    assert!(
        publisher_context
            .create_stream(async_nats::jetstream::stream::Config {
                name: "UNAUTHORIZED_STREAM".to_owned(),
                subjects: vec!["unauthorized.subject".to_owned()],
                ..Default::default()
            })
            .await
            .is_err()
    );
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn outbox_publication_preserves_full_canonical_envelope_and_is_idempotent() -> TestResult {
    let nats = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&nats);
    let config = events_config(&stream, &dlq, &durable, nats.subject_prefix());
    provision(nats.nats_url(), config.clone()).await?;
    let publisher = NatsOutboxPublisher::connect(
        &connection_config(nats.nats_url())?,
        &config,
        DeploymentEnvironment::Test,
    )
    .await?;

    let postgres = PostgresFixture::start().await?;
    let pool = test_database(&postgres).await?;
    let outbox = PostgresOutbox::new(pool.clone(), relay_config())?;
    let envelope = event_envelope(41)?;
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    outbox
        .append(
            &mut transaction,
            &envelope,
            "test",
            "test-41",
            &Destination::try_from(DESTINATION)?,
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
            EventLimits::default(),
        )
        .await?;
    transaction.commit().await?;
    sqlx::query(
        "UPDATE outbox_events
         SET payload = payload || jsonb_build_object('future_top_level', 'preserved')
         WHERE id = $1",
    )
    .bind(envelope.id().as_uuid())
    .execute(&mut *connection)
    .await?;
    let claimed = outbox.claim().await?;
    let leased = claimed
        .first()
        .ok_or_else(|| io::Error::other("outbox event was not claimed"))?;
    let exact_stored_envelope = leased.payload_json().get().as_bytes().to_vec();
    publisher.publish(leased).await?;
    publisher.publish(leased).await?;

    let client = sdk_connect(nats.nats_url()).await?;
    let context = jetstream::new(client);
    let stream_handle = context.get_stream(&stream).await?;
    let state = stream_handle.get_info().await?.state;
    assert_eq!(state.messages, 1);
    let stored = stream_handle.get_raw_message(1).await?;
    let decoded = RawEvent::decode(stored.payload.clone(), config.stream.max_message_size)?;
    assert_eq!(stored.payload.as_ref(), exact_stored_envelope.as_slice());
    assert_eq!(decoded.id(), envelope.id());
    let published_json: Value = serde_json::from_slice(&stored.payload)?;
    let expected_json: Value = serde_json::from_slice(&envelope.encode(EventLimits::default())?)?;
    assert_eq!(published_json.get("data"), expected_json.get("data"));
    assert_eq!(
        published_json.get("future_top_level"),
        Some(&Value::String("preserved".to_owned()))
    );
    pool.close().await?;
    postgres.cleanup().await?;
    nats.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn durable_reconnect_redelivers_same_event_and_lag_decreases_after_ack() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    provision(fixture.nats_url(), config.clone()).await?;
    let (first, _) = raw_event(1)?;
    let (second, _) = raw_event(2)?;
    publish_raw(fixture.nats_url(), &config, &first).await?;
    publish_raw(fixture.nats_url(), &config, &second).await?;
    let status_runtime = NatsJetStreamEvents::connect(
        &connection_config(fixture.nats_url())?,
        config.clone(),
        DeploymentEnvironment::Test,
    )
    .await?;
    assert_eq!(status_runtime.status().await?.lag(), 2);

    let initial_client = sdk_connect(fixture.nats_url()).await?;
    let initial_context = jetstream::new(initial_client.clone());
    let initial_consumer: async_nats::jetstream::consumer::PullConsumer = initial_context
        .get_stream(&stream)
        .await?
        .get_consumer(&durable)
        .await?;
    assert_eq!(initial_consumer.get_info().await?.num_pending, 2);
    let mut batch = initial_consumer
        .fetch()
        .max_messages(1)
        .max_bytes(config.stream.max_message_size)
        .expires(Duration::from_millis(200))
        .messages()
        .await?;
    let delivered = batch
        .next()
        .await
        .ok_or_else(|| io::Error::other("first delivery missing"))??;
    let first_delivery =
        RawEvent::decode(delivered.payload.clone(), config.stream.max_message_size)?;
    assert_eq!(first_delivery.id(), first.id());
    drop(delivered);
    drop(batch);
    initial_client.drain().await?;

    tokio_time::sleep(config.consumer.ack_wait + Duration::from_millis(100)).await;
    let reconnect_client = sdk_connect(fixture.nats_url()).await?;
    let reconnect_context = jetstream::new(reconnect_client);
    let reconnect_consumer: async_nats::jetstream::consumer::PullConsumer = reconnect_context
        .get_stream(&stream)
        .await?
        .get_consumer(&durable)
        .await?;
    let mut redelivery = reconnect_consumer
        .fetch()
        .max_messages(1)
        .max_bytes(config.stream.max_message_size)
        .expires(Duration::from_millis(300))
        .messages()
        .await?;
    let delivered = redelivery
        .next()
        .await
        .ok_or_else(|| io::Error::other("redelivery missing"))??;
    assert!(delivered.info()?.delivered >= 2);
    let redelivered = RawEvent::decode(delivered.payload.clone(), config.stream.max_message_size)?;
    assert_eq!(redelivered.id(), first.id());
    assert!(reconnect_consumer.get_info().await?.num_redelivered >= 1);
    delivered.double_ack_with(AckKind::Ack).await?;
    assert_eq!(reconnect_consumer.get_info().await?.num_pending, 1);
    assert_eq!(status_runtime.status().await?.lag(), 1);
    fixture.cleanup().await?;
    Ok(())
}

struct RetryOnceHandler {
    attempts: AtomicUsize,
    delivery_counts: Mutex<Vec<u32>>,
    completed: Notify,
}

impl EventHandler for RetryOnceHandler {
    fn handle(&self, _: RawEvent, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async move {
            self.delivery_counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(context.delivery_count());
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                HandlerOutcome::Retryable(failure_code("retry_test"))
            } else {
                self.completed.notify_one();
                HandlerOutcome::Success
            }
        }
        .boxed()
    }
}

#[tokio::test]
async fn retryable_nak_redelivers_with_the_configured_durable() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    provision(fixture.nats_url(), config.clone()).await?;
    let runtime = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(fixture.nats_url())?,
            config.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );
    let handler = Arc::new(RetryOnceHandler {
        attempts: AtomicUsize::new(0),
        delivery_counts: Mutex::new(Vec::new()),
        completed: Notify::new(),
    });
    let handle = start_runtime(Arc::clone(&runtime), handler.clone())?;
    publish_raw(fixture.nats_url(), &config, &raw_event(10)?.0).await?;
    tokio_time::timeout(Duration::from_secs(5), handler.completed.notified()).await?;
    handle.begin_drain();
    handle.shutdown().await;
    let counts = handler
        .delivery_counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(counts.len() >= 2);
    assert!(counts[1] >= 2);
    fixture.cleanup().await?;
    Ok(())
}

struct PermanentHandler {
    called: Notify,
}

impl EventHandler for PermanentHandler {
    fn handle(&self, _: RawEvent, _: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async move {
            self.called.notify_one();
            HandlerOutcome::Permanent(failure_code("permanent_test"))
        }
        .boxed()
    }
}

#[tokio::test]
async fn permanent_and_max_delivery_paths_publish_exact_dlq_records_then_ack_source() -> TestResult
{
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    provision(fixture.nats_url(), config.clone()).await?;
    let runtime = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(fixture.nats_url())?,
            config.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );
    let handler = Arc::new(PermanentHandler {
        called: Notify::new(),
    });
    let handle = start_runtime(Arc::clone(&runtime), handler.clone())?;
    let (event, original) = raw_event(20)?;
    publish_raw(fixture.nats_url(), &config, &event).await?;
    tokio_time::timeout(Duration::from_secs(5), handler.called.notified()).await?;
    let record = wait_for_dlq(fixture.nats_url(), &dlq).await?;
    assert_eq!(record.get("event"), Some(&original));
    assert_eq!(
        record.pointer("/delivery/reason"),
        Some(&Value::String("permanent".to_owned()))
    );
    wait_for_consumer_ack(fixture.nats_url(), &stream, &durable).await?;
    handle.begin_drain();
    handle.shutdown().await;

    let second_fixture = NatsFixture::start().await?;
    let (stream2, dlq2, durable2) = fixture_names(&second_fixture);
    let mut config2 = events_config(&stream2, &dlq2, &durable2, second_fixture.subject_prefix());
    config2.consumer.max_deliveries = 2;
    provision(second_fixture.nats_url(), config2.clone()).await?;
    let runtime2 = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(second_fixture.nats_url())?,
            config2.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );
    let handler2 = Arc::new(AlwaysRetryHandler);
    let retry_handle = start_runtime(runtime2, handler2)?;
    publish_raw(second_fixture.nats_url(), &config2, &raw_event(21)?.0).await?;
    let record = wait_for_dlq(second_fixture.nats_url(), &dlq2).await?;
    assert_eq!(
        record.pointer("/delivery/reason"),
        Some(&Value::String("max_deliveries".to_owned()))
    );
    wait_for_consumer_ack(second_fixture.nats_url(), &stream2, &durable2).await?;
    retry_handle.begin_drain();
    retry_handle.shutdown().await;
    second_fixture.cleanup().await?;
    fixture.cleanup().await?;
    Ok(())
}

struct AlwaysRetryHandler;

impl EventHandler for AlwaysRetryHandler {
    fn handle(&self, _: RawEvent, _: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async { HandlerOutcome::Retryable(failure_code("retry_test")) }.boxed()
    }
}

struct PanicHandler;

impl EventHandler for PanicHandler {
    fn handle(&self, _: RawEvent, _: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async move { panic!("sensitive-handler-panic") }.boxed()
    }
}

#[tokio::test]
async fn handler_panic_is_redacted_and_dead_lettered_without_killing_the_task() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    provision(fixture.nats_url(), config.clone()).await?;
    let runtime = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(fixture.nats_url())?,
            config.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );
    let handle = start_runtime(runtime, Arc::new(PanicHandler))?;
    publish_raw(fixture.nats_url(), &config, &raw_event(30)?.0).await?;
    let record = wait_for_dlq(fixture.nats_url(), &dlq).await?;
    assert_eq!(
        record.pointer("/delivery/failure_code"),
        Some(&Value::String("handler_panic".to_owned()))
    );
    assert!(!record.to_string().contains("sensitive-handler-panic"));
    wait_for_consumer_ack(fixture.nats_url(), &stream, &durable).await?;
    handle.begin_drain();
    handle.shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_delivery_is_durably_quarantined_before_source_ack() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    provision(fixture.nats_url(), config.clone()).await?;
    let runtime = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(fixture.nats_url())?,
            config.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );
    let handle = start_runtime(runtime, Arc::new(PanicHandler))?;
    publish_bytes(
        fixture.nats_url(),
        &config,
        b"{not-valid-json",
        "malformed-delivery".to_owned(),
    )
    .await?;
    let record = wait_for_dlq(fixture.nats_url(), &dlq).await?;
    assert_eq!(
        record.pointer("/delivery/reason"),
        Some(&Value::String("invalid_event".to_owned()))
    );
    assert_eq!(
        record.pointer("/invalid_event/encoding"),
        Some(&Value::String("hex".to_owned()))
    );
    assert_eq!(
        record.pointer("/invalid_event/bytes"),
        Some(&Value::String("7b6e6f742d76616c69642d6a736f6e".to_owned()))
    );
    wait_for_consumer_ack(fixture.nats_url(), &stream, &durable).await?;
    handle.begin_drain();
    handle.shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_dlq_failure_leaves_the_source_unacknowledged() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    provision(fixture.nats_url(), config.clone()).await?;
    let runtime = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(fixture.nats_url())?,
            config.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );

    let client = sdk_connect(fixture.nats_url()).await?;
    let context = jetstream::new(client);
    let mut drift = context.get_stream(&dlq).await?.get_info().await?.config;
    drift.subjects = vec![format!("{}.disabled", fixture.subject_prefix())];
    context.update_stream(drift).await?;

    let handle = start_runtime(runtime, Arc::new(PanicHandler))?;
    publish_bytes(
        fixture.nats_url(),
        &config,
        b"{not-valid-json",
        "malformed-dlq-failure".to_owned(),
    )
    .await?;
    tokio_time::sleep(config.consumer.ack_wait + Duration::from_millis(150)).await;
    let client = sdk_connect(fixture.nats_url()).await?;
    let context = jetstream::new(client);
    let consumer: async_nats::jetstream::consumer::PullConsumer = context
        .get_stream(&stream)
        .await?
        .get_consumer(&durable)
        .await?;
    assert_eq!(consumer.get_info().await?.ack_floor.stream_sequence, 0);
    assert_eq!(
        context
            .get_stream(&dlq)
            .await?
            .get_info()
            .await?
            .state
            .messages,
        0
    );
    handle.begin_drain();
    handle.shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

struct BlockingHandler {
    calls: AtomicUsize,
    started: Notify,
}

impl EventHandler for BlockingHandler {
    fn handle(&self, _: RawEvent, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            context.cancelled().await;
            HandlerOutcome::Success
        }
        .boxed()
    }
}

#[tokio::test]
async fn drain_stops_new_fetch_and_leaves_unfinished_work_unacknowledged() -> TestResult {
    let fixture = NatsFixture::start().await?;
    let (stream, dlq, durable) = fixture_names(&fixture);
    let mut config = events_config(&stream, &dlq, &durable, fixture.subject_prefix());
    config.delivery.concurrency = 1;
    config.delivery.handler_timeout = Duration::from_secs(5);
    config.delivery.shutdown_timeout = Duration::from_secs(6);
    config.consumer.ack_wait = Duration::from_secs(10);
    provision(fixture.nats_url(), config.clone()).await?;
    let runtime = Arc::new(
        NatsJetStreamEvents::connect(
            &connection_config(fixture.nats_url())?,
            config.clone(),
            DeploymentEnvironment::Test,
        )
        .await?,
    );
    let handler = Arc::new(BlockingHandler {
        calls: AtomicUsize::new(0),
        started: Notify::new(),
    });
    let handle = start_runtime(runtime, handler.clone())?;
    publish_raw(fixture.nats_url(), &config, &raw_event(50)?.0).await?;
    publish_raw(fixture.nats_url(), &config, &raw_event(51)?.0).await?;
    tokio_time::timeout(Duration::from_secs(5), handler.started.notified()).await?;
    handle.begin_drain();
    tokio_time::sleep(Duration::from_millis(150)).await;
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    handle.shutdown().await;

    let client = sdk_connect(fixture.nats_url()).await?;
    let context = jetstream::new(client);
    let consumer: async_nats::jetstream::consumer::PullConsumer = context
        .get_stream(&stream)
        .await?
        .get_consumer(&durable)
        .await?;
    let info = consumer.get_info().await?;
    assert_eq!(info.ack_floor.stream_sequence, 0);
    assert!(info.num_ack_pending >= 1);
    fixture.cleanup().await?;
    Ok(())
}

fn start_runtime<H: EventHandler>(
    runtime: Arc<NatsJetStreamEvents>,
    handler: Arc<H>,
) -> TestResult<omnius_runtime::SupervisorHandle> {
    let mut supervisor = Supervisor::new();
    supervisor.register(runtime.task_spec(handler))?;
    Ok(supervisor.start()?)
}

async fn wait_for_dlq(url: &SecretString, dlq_stream: &str) -> TestResult<Value> {
    let client = sdk_connect(url).await?;
    let context = jetstream::new(client);
    let stream = context.get_stream(dlq_stream).await?;
    wait_until(|| {
        let stream = stream.clone();
        async move { Ok(stream.get_info().await?.state.messages > 0) }
    })
    .await?;
    let message = stream.get_raw_message(1).await?;
    Ok(serde_json::from_slice(&message.payload)?)
}

async fn wait_for_consumer_ack(
    url: &SecretString,
    stream_name: &str,
    durable_name: &str,
) -> TestResult {
    let client = sdk_connect(url).await?;
    let context = jetstream::new(client);
    let consumer: async_nats::jetstream::consumer::PullConsumer = context
        .get_stream(stream_name)
        .await?
        .get_consumer(durable_name)
        .await?;
    wait_until(|| {
        let consumer = consumer.clone();
        async move {
            let info = consumer.get_info().await?;
            Ok(info.num_ack_pending == 0 && info.ack_floor.stream_sequence > 0)
        }
    })
    .await
}

fn failure_code(value: &str) -> FailureCode {
    FailureCode::try_from(value)
        .unwrap_or_else(|error| panic!("invalid static failure code: {error}"))
}

fn relay_config() -> OutboxConfig {
    OutboxConfig {
        enabled: true,
        lease_owner: "events-nats-test-relay".to_owned(),
        claim_batch: 1,
        poll_interval: Duration::from_millis(10),
        lease_duration: Duration::from_secs(10),
        publication_timeout: Duration::from_secs(2),
        retry_delay: Duration::from_secs(1),
        shutdown_timeout: Duration::from_secs(4),
        max_attempts: 5,
        retention: Duration::from_hours(24),
        cleanup_batch: 20,
        restart: omnius_outbox::OutboxRestartConfig::default(),
    }
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-events-nats-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
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

async fn test_database(fixture: &PostgresFixture) -> TestResult<PostgresPool> {
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(SCHEMA_HEAD, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(pool)
}
