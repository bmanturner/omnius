use std::{collections::BTreeMap, fmt, sync::Arc, time::Instant};

use async_nats::jetstream::{self, message::PublishMessage};
use futures::{FutureExt as _, future::BoxFuture};
use metrics::{counter, histogram};
use rsk_config::DeploymentEnvironment;
use rsk_outbox::{
    FailureClass, LeasedOutboxEvent, OutboxPublisher, PublishError as OutboxPublishError,
};

use crate::{
    config::{NatsConnectionConfig, NatsEventsConfig},
    connection,
    error::NatsEventsError,
    event::RawEvent,
    resource::stream_config,
    verification::verify_stream,
};

/// `JetStream` implementation of the transactional outbox publisher seam.
#[derive(Clone)]
pub struct NatsOutboxPublisher {
    jetstream: jetstream::Context,
    routes: Arc<BTreeMap<String, String>>,
    stream_name: Arc<str>,
    max_message_size: usize,
}

impl fmt::Debug for NatsOutboxPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsOutboxPublisher")
            .field("route_count", &self.routes.len())
            .field("stream", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl NatsOutboxPublisher {
    /// Connects a publication-only identity and exactly verifies the declared main stream.
    ///
    /// This constructor never creates or updates `JetStream` resources.
    ///
    /// # Errors
    ///
    /// Returns a safe error for invalid configuration, access denial, or stream drift.
    pub async fn connect(
        connection_config: &NatsConnectionConfig,
        config: &NatsEventsConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, NatsEventsError> {
        config.validate_for(environment)?;
        let connected = connection::connect(connection_config, environment).await?;
        let expected = stream_config(&config.stream, false)?;
        verify_stream(&connected.jetstream, &expected).await?;
        counter!("rsk_events_nats_verification_total", "status" => "ok").increment(1);
        Ok(Self::from_verified(
            connected.jetstream,
            config.routes.clone(),
            config.stream.name.clone(),
            config.stream.max_message_size,
        ))
    }

    pub(crate) fn from_verified(
        jetstream: jetstream::Context,
        routes: BTreeMap<String, String>,
        stream_name: String,
        max_message_size: usize,
    ) -> Self {
        Self {
            jetstream,
            routes: Arc::new(routes),
            stream_name: Arc::from(stream_name),
            max_message_size,
        }
    }

    async fn publish_leased(&self, event: &LeasedOutboxEvent) -> Result<(), NatsEventsError> {
        let subject = self
            .routes
            .get(event.destination())
            .ok_or(NatsEventsError::UnknownDestination)?;
        let raw = RawEvent::from_leased(event, self.max_message_size)?;
        self.publish_to(subject, &raw).await
    }

    pub(crate) async fn publish_to(
        &self,
        subject: &str,
        event: &RawEvent,
    ) -> Result<(), NatsEventsError> {
        let id = event.id().to_string();
        let ack = self
            .jetstream
            .send_publish(
                subject.to_owned(),
                PublishMessage::build()
                    .payload(event.bytes())
                    .message_id(&id),
            )
            .await
            .map_err(|_| NatsEventsError::Publish)?
            .await
            .map_err(|_| NatsEventsError::Publish)?;
        if ack.stream != self.stream_name.as_ref() {
            return Err(NatsEventsError::AckMismatch);
        }
        Ok(())
    }
}

impl OutboxPublisher for NatsOutboxPublisher {
    fn publish<'event>(
        &'event self,
        event: &'event LeasedOutboxEvent,
    ) -> BoxFuture<'event, Result<(), OutboxPublishError>> {
        async move {
            let started = Instant::now();
            let result = self.publish_leased(event).await;
            let status = match &result {
                Ok(()) => "published",
                Err(NatsEventsError::UnknownDestination | NatsEventsError::InvalidEvent) => {
                    "permanent"
                }
                Err(_) => "retryable",
            };
            counter!("rsk_events_nats_publish_total", "status" => status).increment(1);
            histogram!("rsk_events_nats_publish_duration_seconds", "status" => status)
                .record(started.elapsed().as_secs_f64());
            result.map_err(outbox_error)
        }
        .boxed()
    }
}

fn outbox_error(error: NatsEventsError) -> OutboxPublishError {
    let class = match error {
        NatsEventsError::UnknownDestination => failure_class("unknown_destination"),
        NatsEventsError::InvalidEvent => failure_class("invalid_event"),
        NatsEventsError::AckMismatch | NatsEventsError::Drift => failure_class("nats_drift"),
        _ => failure_class("nats_unavailable"),
    };
    OutboxPublishError::new(class)
}

fn failure_class(value: &'static str) -> FailureClass {
    let Ok(class) = FailureClass::try_from(value) else {
        unreachable!("static NATS outbox failure class must be valid")
    };
    class
}
