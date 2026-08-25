//! Real Core NATS fan-out, loss, lifecycle, and least-privilege contracts.

use std::{error::Error, io, time::Duration};

use bytes::Bytes;
use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use rsk_events_nats::{
    NatsAuthConfig, NatsConnectionConfig, NatsCoreFanout, NatsCoreFanoutConfig,
    NatsCoreFanoutConfigError, NatsCoreFanoutLifecycle, NatsCoreFanoutReceiver,
    NatsCoreFanoutStatus, NatsCoreFanoutStatusError,
};
use rsk_runtime::{Supervisor, SupervisorHandle, TaskSpec, TaskStatus};
use rsk_test_support::NatsCoreFanoutRoleFixture;
use tokio::time;
use url::Url;

const WAIT: Duration = Duration::from_secs(5);

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

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
    config.connection_timeout = Duration::from_secs(2);
    config.operation_timeout = Duration::from_secs(2);
    Ok(config)
}

fn fanout_config(subject: &str, ingress_capacity: usize) -> NatsCoreFanoutConfig {
    let mut config = NatsCoreFanoutConfig::new(subject.to_owned());
    config.ingress_capacity = ingress_capacity;
    config.max_message_bytes = 1_024;
    config
}

fn start_listener(task: TaskSpec) -> TestResult<SupervisorHandle> {
    let mut supervisor = Supervisor::new();
    supervisor.register(task)?;
    Ok(supervisor.start()?)
}

async fn await_ready(status: &mut NatsCoreFanoutStatus) -> TestResult {
    time::timeout(WAIT, status.wait_until_ready()).await??;
    Ok(())
}

async fn await_lifecycle(
    status: &mut NatsCoreFanoutStatus,
    expected: NatsCoreFanoutLifecycle,
) -> TestResult {
    time::timeout(WAIT, async {
        while status.lifecycle() != expected {
            status.changed().await?;
        }
        Ok::<(), rsk_events_nats::NatsCoreFanoutStatusError>(())
    })
    .await??;
    Ok(())
}

async fn receive(receiver: &mut NatsCoreFanoutReceiver) -> TestResult<Bytes> {
    let message = time::timeout(WAIT, receiver.recv())
        .await?
        .ok_or_else(|| io::Error::other("fan-out receiver closed"))?;
    Ok(message.into_payload())
}

#[test]
fn fanout_configuration_requires_one_exact_subject() {
    let mut config = fanout_config("private.realtime", 8);
    config.subject = "private.*".to_owned();
    assert_eq!(
        config.validate(),
        Err(NatsCoreFanoutConfigError::InvalidSubject)
    );
}

#[test]
fn fanout_configuration_bounds_combined_local_retention() {
    let mut config = fanout_config("private.realtime", 65_536);
    config.max_message_bytes = 16 * 1024 * 1024;
    assert_eq!(
        config.validate(),
        Err(NatsCoreFanoutConfigError::InvalidIngressBounds)
    );
}

#[test]
fn fanout_configuration_debug_redacts_subject() {
    let config = fanout_config("private.realtime", 8);
    assert!(!format!("{config:?}").contains("private"));
}

#[tokio::test]
async fn denied_exact_subscription_never_becomes_ready_and_retries_to_stopped() -> TestResult {
    let fixture = NatsCoreFanoutRoleFixture::start().await?;
    let mut config = fanout_config(fixture.subject(), 8);
    config.restart.max_restarts = 1;
    config.restart.initial_backoff = Duration::from_millis(500);
    config.restart.max_backoff = Duration::from_millis(500);
    config.restart.jitter_percent = 0;
    let fanout = NatsCoreFanout::connect(
        &connection_config(fixture.denied_sub_url())?,
        config,
        DeploymentEnvironment::Test,
    )
    .await?;
    let (publisher, _receiver, mut status, task) = fanout.into_parts();
    let mut readiness_status = status.clone();
    let readiness = tokio::spawn(async move { readiness_status.wait_until_ready().await });
    publisher
        .publish(Bytes::from_static(b"publish-is-allowed"))
        .await?;
    let handle = start_listener(task)?;

    await_lifecycle(&mut status, NatsCoreFanoutLifecycle::Degraded).await?;
    time::timeout(WAIT, async {
        loop {
            let restarting = handle.snapshots().first().is_some_and(|snapshot| {
                snapshot.status == TaskStatus::Restarting && snapshot.restarts == 1
            });
            if restarting {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(!status.is_ready());

    let readiness = time::timeout(WAIT, readiness).await??;
    assert_eq!(readiness, Err(NatsCoreFanoutStatusError::Stopped));
    let snapshots = handle.snapshots();
    let snapshot = snapshots
        .first()
        .ok_or_else(|| io::Error::other("listener task snapshot is missing"))?;
    assert_eq!(
        (snapshot.status, snapshot.restarts),
        (TaskStatus::Degraded, 1)
    );
    assert_eq!(status.lifecycle(), NatsCoreFanoutLifecycle::Stopped);

    handle.shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn separately_connected_instances_both_receive_post_ready_publication() -> TestResult {
    let fixture = NatsCoreFanoutRoleFixture::start().await?;
    let connection = connection_config(fixture.runtime_url())?;
    let first = NatsCoreFanout::connect(
        &connection,
        fanout_config(fixture.subject(), 8),
        DeploymentEnvironment::Test,
    )
    .await?;
    let second = NatsCoreFanout::connect(
        &connection,
        fanout_config(fixture.subject(), 8),
        DeploymentEnvironment::Test,
    )
    .await?;
    let (publisher, mut first_receiver, mut first_status, first_task) = first.into_parts();
    let (_, mut second_receiver, mut second_status, second_task) = second.into_parts();
    let first_handle = start_listener(first_task)?;
    let second_handle = start_listener(second_task)?;
    await_ready(&mut first_status).await?;
    await_ready(&mut second_status).await?;

    let expected = Bytes::from_static(b"post-ready");
    publisher.publish(expected.clone()).await?;
    let first_message = receive(&mut first_receiver).await?;
    let second_message = receive(&mut second_receiver).await?;
    assert_eq!(
        (first_message, second_message),
        (expected.clone(), expected)
    );

    first_handle.shutdown().await;
    second_handle.shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn publication_before_subscription_is_absent_and_never_replayed() -> TestResult {
    let fixture = NatsCoreFanoutRoleFixture::start().await?;
    let fanout = NatsCoreFanout::connect(
        &connection_config(fixture.runtime_url())?,
        fanout_config(fixture.subject(), 8),
        DeploymentEnvironment::Test,
    )
    .await?;
    let (publisher, mut receiver, mut status, task) = fanout.into_parts();
    publisher.publish(Bytes::from_static(b"before")).await?;
    let handle = start_listener(task)?;
    await_ready(&mut status).await?;
    assert!(
        time::timeout(Duration::from_millis(200), receiver.recv())
            .await
            .is_err()
    );

    publisher.publish(Bytes::from_static(b"after")).await?;
    assert_eq!(receive(&mut receiver).await?, Bytes::from_static(b"after"));

    handle.shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn full_local_ingress_drops_without_blocking_listener_cancellation() -> TestResult {
    let fixture = NatsCoreFanoutRoleFixture::start().await?;
    let fanout = NatsCoreFanout::connect(
        &connection_config(fixture.runtime_url())?,
        fanout_config(fixture.subject(), 2),
        DeploymentEnvironment::Test,
    )
    .await?;
    let (publisher, mut receiver, mut status, task) = fanout.into_parts();
    let handle = start_listener(task)?;
    await_ready(&mut status).await?;
    for _ in 0..16 {
        publisher.publish(Bytes::from_static(b"fill")).await?;
    }
    time::timeout(WAIT, async {
        while receiver.len() != 2 {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert_eq!(status.lifecycle(), NatsCoreFanoutLifecycle::Ready);

    handle.request_shutdown();
    await_lifecycle(&mut status, NatsCoreFanoutLifecycle::Stopped).await?;
    assert_eq!(receive(&mut receiver).await?, Bytes::from_static(b"fill"));
    assert_eq!(receive(&mut receiver).await?, Bytes::from_static(b"fill"));
    assert!(receiver.try_recv().is_err());

    handle.shutdown().await;
    fixture
        .cleanup()
        .await
        .map_err(|error| io::Error::other(format!("fixture cleanup failed: {error}")))?;
    Ok(())
}

#[tokio::test]
async fn cancellation_stops_intake_and_exposes_terminal_status() -> TestResult {
    let fixture = NatsCoreFanoutRoleFixture::start().await?;
    let fanout = NatsCoreFanout::connect(
        &connection_config(fixture.runtime_url())?,
        fanout_config(fixture.subject(), 8),
        DeploymentEnvironment::Test,
    )
    .await?;
    let (publisher, mut receiver, mut status, task) = fanout.into_parts();
    let handle = start_listener(task)?;
    await_ready(&mut status).await?;

    handle.request_shutdown();
    await_lifecycle(&mut status, NatsCoreFanoutLifecycle::Stopped)
        .await
        .map_err(|error| io::Error::other(format!("await stopped failed: {error}")))?;
    publisher
        .publish(Bytes::from_static(b"after-stop"))
        .await
        .map_err(|error| io::Error::other(format!("post-stop publish failed: {error}")))?;
    let after_stop = time::timeout(Duration::from_millis(200), receiver.recv()).await;
    assert!(!matches!(after_stop, Ok(Some(_))));
    assert_eq!(status.lifecycle(), NatsCoreFanoutLifecycle::Stopped);

    handle.shutdown().await;
    fixture
        .cleanup()
        .await
        .map_err(|error| io::Error::other(format!("fixture cleanup failed: {error}")))?;
    Ok(())
}
