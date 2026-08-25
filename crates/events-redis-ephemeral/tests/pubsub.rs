//! Real Redis contracts for bounded ephemeral fan-out and degraded listener lifecycle.

use std::{error::Error, io, time::Duration};

use redis::cmd;
use rsk_config::{DeploymentEnvironment, ExposeSecret as _};
use rsk_events_redis_ephemeral::{
    PublishError, RedisEphemeralConfig, RedisEphemeralConfigError, RedisEphemeralEvents,
    RedisEphemeralListenerState, RedisEphemeralListenerStatus, RedisEphemeralReceiver,
    RedisEphemeralRestartConfig,
};
use rsk_redis_core::{RedisCommandFamily, RedisConfig, RedisCore, RedisReconnectConfig};
use rsk_runtime::{Criticality, Supervisor, SupervisorHandle, TaskStatus};
use rsk_test_support::RedisFixture;

fn redis_config(fixture: &RedisFixture) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(2),
        startup_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(1),
        client_name: "rsk-events-integration".to_owned(),
        key_prefix: fixture.namespace().replace(':', "-"),
        schema_version: "v1".to_owned(),
        max_value_bytes: 1024 * 1024,
        reconnect: RedisReconnectConfig::default(),
    }
}

async fn connected(fixture: &RedisFixture) -> Result<RedisCore, Box<dyn Error>> {
    RedisCore::connect(&redis_config(fixture), DeploymentEnvironment::Test)
        .await?
        .ok_or_else(|| io::Error::other("enabled Redis unexpectedly disabled").into())
}

fn provider_config(
    channels: &[&str],
    delivery_capacity: usize,
    max_message_bytes: usize,
) -> RedisEphemeralConfig {
    RedisEphemeralConfig {
        enabled: true,
        channels: channels
            .iter()
            .map(|channel| (*channel).to_owned())
            .collect(),
        delivery_capacity,
        max_message_bytes,
        operation_timeout: Duration::from_millis(300),
        read_poll_timeout: Duration::from_millis(20),
        shutdown_timeout: Duration::from_secs(1),
        restart: RedisEphemeralRestartConfig {
            max_restarts: 8,
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(50),
            jitter_percent: 0,
        },
    }
}

fn start(task: rsk_runtime::TaskSpec) -> Result<SupervisorHandle, Box<dyn Error>> {
    let mut supervisor = Supervisor::new();
    supervisor.register(task)?;
    Ok(supervisor.start()?)
}

async fn wait_for_numsub(
    redis: &RedisCore,
    physical_channel: &str,
    expected: u64,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let mut command = cmd("PUBSUB");
        command.arg("NUMSUB").arg(physical_channel);
        if redis
            .query::<(String, u64)>(RedisCommandFamily::PubSub, command)
            .await
            .is_ok_and(|(_, subscribers)| subscribers == expected)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Redis subscription count did not become ready",
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_restart(handle: &SupervisorHandle) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if handle
            .snapshots()
            .first()
            .is_some_and(|snapshot| snapshot.restarts > 0)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "degraded listener did not restart",
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_queue_len(
    receiver: &RedisEphemeralReceiver,
    expected: usize,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if receiver.len() == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "bounded delivery queue did not reach expected occupancy",
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn wait_for_listener_state(
    status: &mut RedisEphemeralListenerStatus,
    expected: RedisEphemeralListenerState,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if status.state() == expected {
            return Ok(());
        }
        match tokio::time::timeout_at(deadline, status.changed()).await {
            Ok(Some(state)) if state == expected => return Ok(()),
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(io::Error::other(
                    "listener status publisher closed before the expected state",
                )
                .into());
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "listener did not reach the expected state",
                )
                .into());
            }
        }
    }
}

async fn receive(
    receiver: &mut RedisEphemeralReceiver,
) -> Result<rsk_events_redis_ephemeral::EphemeralMessage, Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await?
        .ok_or_else(|| io::Error::other("ephemeral listener closed unexpectedly").into())
}

#[tokio::test]
async fn static_subscriptions_fan_out_exactly_and_resubscribe_after_disconnect()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let config = provider_config(&["orders", "alerts"], 8, 64);
    let first = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let second = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let (publisher, mut first_receiver, first_task) = first.into_parts();
    let (second_publisher, mut second_receiver, second_task) = second.into_parts();
    let first_handle = start(first_task)?;
    let second_handle = start(second_task)?;
    let orders = redis.key(&["events", "orders"])?;
    let alerts = redis.key(&["events", "alerts"])?;
    wait_for_numsub(&redis, &orders, 2).await?;
    wait_for_numsub(&redis, &alerts, 2).await?;

    assert_eq!(
        publisher
            .publish("orders", b"created")
            .await?
            .receiver_count(),
        2
    );
    let first_message = receive(&mut first_receiver).await?;
    let second_message = receive(&mut second_receiver).await?;
    assert_eq!(
        (first_message.channel(), first_message.payload()),
        ("orders", b"created".as_slice())
    );
    assert_eq!(
        (second_message.channel(), second_message.payload()),
        ("orders", b"created".as_slice())
    );

    let mut kill = cmd("CLIENT");
    kill.arg("KILL").arg("TYPE").arg("PUBSUB");
    assert_eq!(
        redis.query::<u64>(RedisCommandFamily::PubSub, kill).await?,
        2
    );
    wait_for_restart(&first_handle).await?;
    wait_for_restart(&second_handle).await?;
    wait_for_numsub(&redis, &orders, 2).await?;
    wait_for_numsub(&redis, &alerts, 2).await?;

    assert_eq!(
        publisher
            .publish("alerts", b"restored")
            .await?
            .receiver_count(),
        2
    );
    assert_eq!(receive(&mut first_receiver).await?.payload(), b"restored");
    assert_eq!(receive(&mut second_receiver).await?.payload(), b"restored");

    let first_report = first_handle.shutdown().await;
    let second_report = second_handle.shutdown().await;
    assert!(first_report.forced.is_empty());
    assert!(second_report.forced.is_empty());
    drop(second_publisher);
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn listener_status_is_cloneable_and_tracks_retry_and_shutdown() -> Result<(), Box<dyn Error>>
{
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let mut config = provider_config(&["status"], 4, 64);
    config.restart.initial_backoff = Duration::from_millis(150);
    config.restart.max_backoff = Duration::from_millis(150);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let mut status = provider.listener_status();
    let readiness = status.clone();
    assert_eq!(status.state(), RedisEphemeralListenerState::Connecting);
    assert!(!readiness.is_ready());
    let (publisher, receiver, task) = provider.into_parts();
    let physical = redis.key(&["events", "status"])?;
    let handle = start(task)?;

    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Subscribed).await?;
    assert!(readiness.is_ready());
    wait_for_numsub(&redis, &physical, 1).await?;

    let mut kill = cmd("CLIENT");
    kill.arg("KILL").arg("TYPE").arg("PUBSUB");
    assert_eq!(
        redis.query::<u64>(RedisCommandFamily::PubSub, kill).await?,
        1
    );
    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Disconnected).await?;
    assert!(!readiness.is_ready());
    wait_for_restart(&handle).await?;
    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Subscribed).await?;
    assert!(readiness.is_ready());

    assert!(handle.shutdown().await.forced.is_empty());
    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Stopped).await?;
    assert!(!readiness.is_ready());
    drop(receiver);
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn publish_before_subscription_has_no_replay() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let config = provider_config(&["updates"], 4, 64);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let (publisher, mut receiver, task) = provider.into_parts();

    assert_eq!(
        publisher
            .publish("updates", b"before")
            .await?
            .receiver_count(),
        0
    );
    let handle = start(task)?;
    let physical = redis.key(&["events", "updates"])?;
    wait_for_numsub(&redis, &physical, 1).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err()
    );

    publisher.publish("updates", b"after").await?;
    assert_eq!(receive(&mut receiver).await?.payload(), b"after");
    assert!(handle.shutdown().await.forced.is_empty());
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn capacity_one_drops_for_a_slow_consumer_without_stopping_delivery()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let config = provider_config(&["slow"], 1, 64);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let (publisher, mut receiver, task) = provider.into_parts();
    let handle = start(task)?;
    let physical = redis.key(&["events", "slow"])?;
    wait_for_numsub(&redis, &physical, 1).await?;

    publisher.publish("slow", b"retained").await?;
    wait_for_queue_len(&receiver, 1).await?;
    publisher.publish("slow", b"dropped").await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(receiver.len(), 1);
    assert_eq!(receive(&mut receiver).await?.payload(), b"retained");
    assert!(receiver.try_recv().is_err());

    publisher.publish("slow", b"later").await?;
    assert_eq!(receive(&mut receiver).await?.payload(), b"later");
    assert!(handle.shutdown().await.forced.is_empty());
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn local_and_foreign_oversize_messages_are_rejected_without_stopping_listener()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let config = provider_config(&["bounded"], 4, 4);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let (publisher, mut receiver, task) = provider.into_parts();
    let handle = start(task)?;
    let physical = redis.key(&["events", "bounded"])?;
    wait_for_numsub(&redis, &physical, 1).await?;

    assert_eq!(
        publisher.publish("bounded", b"12345").await,
        Err(PublishError::MessageTooLarge)
    );
    let mut foreign = cmd("PUBLISH");
    foreign.arg(&physical).arg(b"12345".as_slice());
    assert_eq!(
        redis
            .query::<u64>(RedisCommandFamily::PubSub, foreign)
            .await?,
        1
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(receiver.is_empty());

    publisher.publish("bounded", b"1234").await?;
    assert_eq!(receive(&mut receiver).await?.payload(), b"1234");
    assert!(handle.shutdown().await.forced.is_empty());
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn dropping_the_sole_receiver_stops_the_quiet_subscription() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let config = provider_config(&["quiet"], 1, 64);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let mut status = provider.listener_status();
    let (publisher, receiver, task) = provider.into_parts();
    let physical = redis.key(&["events", "quiet"])?;
    let handle = start(task)?;
    wait_for_numsub(&redis, &physical, 1).await?;

    drop(receiver);
    wait_for_numsub(&redis, &physical, 0).await?;
    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Stopped).await?;

    assert!(handle.shutdown().await.forced.is_empty());
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn unavailable_pubsub_starts_degraded_and_shutdown_never_forces_listener()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let mut config = provider_config(&["degraded"], 4, 64);
    config.restart.initial_backoff = Duration::from_millis(150);
    config.restart.max_backoff = Duration::from_millis(150);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let mut status = provider.listener_status();
    let (publisher, receiver, task) = provider.into_parts();
    fixture.cleanup().await?;

    let handle = start(task)?;
    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Disconnected).await?;
    wait_for_restart(&handle).await?;
    let snapshot = handle
        .snapshots()
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("listener task snapshot missing"))?;
    assert_eq!(snapshot.criticality, Criticality::Degraded);
    assert!(matches!(
        snapshot.status,
        TaskStatus::Running | TaskStatus::Restarting | TaskStatus::Degraded
    ));
    assert!(!handle.is_shutdown_requested());
    let report = handle.shutdown().await;
    wait_for_listener_state(&mut status, RedisEphemeralListenerState::Stopped).await?;
    assert!(report.forced.is_empty());
    assert!(!report.fatal);
    drop(receiver);
    drop(publisher);
    drop(redis);
    Ok(())
}

#[tokio::test]
async fn diagnostics_do_not_reveal_url_channel_or_payload() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture).await?;
    let config = provider_config(&["private-channel"], 2, 4);
    let provider = RedisEphemeralEvents::new(&config, Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled provider was disabled"))?;
    let publisher = provider.publisher();
    let listener_status = provider.listener_status();
    let Err(channel_error) = publisher
        .publish("unconfigured-private-channel", b"safe")
        .await
    else {
        return Err(io::Error::other("unknown channel was accepted").into());
    };
    let Err(payload_error) = publisher
        .publish("private-channel", b"secret-payload")
        .await
    else {
        return Err(io::Error::other("oversized payload was accepted").into());
    };
    let diagnostics = format!(
        "{config:?} {provider:?} {publisher:?} {listener_status:?} {:?} \
         {channel_error:?} {channel_error} {payload_error:?} {payload_error}",
        listener_status.state()
    );

    assert!(!diagnostics.contains(fixture.redis_url().expose_secret()));
    assert!(!diagnostics.contains("private-channel"));
    assert!(!diagnostics.contains("secret-payload"));
    drop(provider);
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[test]
fn disabled_and_unknown_field_configuration_contracts_are_explicit() -> Result<(), Box<dyn Error>> {
    assert!(RedisEphemeralEvents::new(&RedisEphemeralConfig::default(), None)?.is_none());
    assert!(
        serde_json::from_str::<RedisEphemeralConfig>(
            r#"{"enabled":false,"unexpected_setting":true}"#
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn duplicate_and_nonportable_channels_are_rejected() {
    let duplicate = provider_config(&["same", "same"], 1, 1);
    let nonportable = provider_config(&["tenant:secret"], 1, 1);
    assert!(duplicate.validate().is_err());
    assert!(nonportable.validate().is_err());
}

#[test]
fn combined_delivery_limits_cannot_exceed_the_retained_byte_budget() {
    let config = provider_config(&["bounded"], 65_536, 16 * 1024 * 1024);
    assert_eq!(
        config.validate(),
        Err(RedisEphemeralConfigError::InvalidDeliveryBudget)
    );
}

#[tokio::test]
async fn provider_message_limit_cannot_exceed_redis_core_limit() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let mut core_config = redis_config(&fixture);
    core_config.max_value_bytes = 4;
    let redis = RedisCore::connect(&core_config, DeploymentEnvironment::Test)
        .await?
        .ok_or_else(|| io::Error::other("enabled Redis unexpectedly disabled"))?;
    let provider_config = provider_config(&["events"], 1, 5);

    assert!(matches!(
        RedisEphemeralEvents::new(&provider_config, Some(redis)),
        Err(RedisEphemeralConfigError::InvalidMessageLimit)
    ));

    fixture.cleanup().await?;
    Ok(())
}
