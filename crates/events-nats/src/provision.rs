use std::{fmt, sync::Arc, time::Duration};

use async_nats::{
    Client,
    jetstream::{
        self,
        consumer::{PullConsumer, pull},
        stream,
    },
};
use metrics::counter;
use rsk_config::DeploymentEnvironment;

use crate::{
    config::{NatsConnectionConfig, NatsEventsConfig},
    connection,
    error::NatsEventsError,
    resource::{
        consumer_config_matches_declared, consumer_config_with_declared_updates,
        expected_resources, generic_consumer_config, stream_config_matches_declared,
        stream_config_with_declared_updates, subject_set_is_subset,
    },
};

/// Result of one explicit, idempotent provisioning pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningReport {
    main_stream_changed: bool,
    dlq_stream_changed: bool,
    consumer_changed: bool,
}

impl ProvisioningReport {
    /// Whether any declared server resource was created or safely updated.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.main_stream_changed || self.dlq_stream_changed || self.consumer_changed
    }

    /// Whether the main stream changed.
    #[must_use]
    pub const fn main_stream_changed(self) -> bool {
        self.main_stream_changed
    }

    /// Whether the DLQ stream changed.
    #[must_use]
    pub const fn dlq_stream_changed(self) -> bool {
        self.dlq_stream_changed
    }

    /// Whether the durable consumer changed.
    #[must_use]
    pub const fn consumer_changed(self) -> bool {
        self.consumer_changed
    }
}

/// Administrative `JetStream` provisioner. Runtime constructors never call this API.
pub struct NatsJetStreamProvisioner {
    client: Client,
    jetstream: jetstream::Context,
    config: Arc<NatsEventsConfig>,
}

impl fmt::Debug for NatsJetStreamProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsJetStreamProvisioner")
            .field("connection", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl NatsJetStreamProvisioner {
    /// Connects an administrative identity without creating or updating resources.
    ///
    /// # Errors
    ///
    /// Returns a safe error when configuration or connection establishment fails.
    pub async fn connect(
        connection_config: &NatsConnectionConfig,
        config: NatsEventsConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, NatsEventsError> {
        config.validate_for(environment)?;
        let connected = connection::connect(connection_config, environment).await?;
        Ok(Self {
            client: connected.client,
            jetstream: connected.jetstream,
            config: Arc::new(config),
        })
    }

    /// Creates missing resources and applies only additive or limit-strengthening updates.
    ///
    /// Subject removal, weaker retention, storage changes, smaller limits, fewer replicas, and
    /// consumer filter changes are rejected rather than silently applied.
    ///
    /// # Errors
    ///
    /// Returns [`NatsEventsError::UnsafeDrift`] for destructive drift and a value-free
    /// provisioning error for SDK or server failure.
    pub async fn provision(&self) -> Result<ProvisioningReport, NatsEventsError> {
        let (main, dlq, consumer) = expected_resources(&self.config)?;
        let main_stream_changed = provision_stream(&self.jetstream, &main).await?;
        let dlq_stream_changed = provision_stream(&self.jetstream, &dlq).await?;
        let stream = self
            .jetstream
            .get_stream(&main.name)
            .await
            .map_err(|_| NatsEventsError::Provision)?;
        let consumer_changed =
            provision_consumer(&stream, &self.config.consumer.durable_name, &consumer).await?;
        self.client
            .flush()
            .await
            .map_err(|_| NatsEventsError::Provision)?;
        counter!("rsk_events_nats_provision_total", "status" => "ok").increment(1);
        Ok(ProvisioningReport {
            main_stream_changed,
            dlq_stream_changed,
            consumer_changed,
        })
    }
}

async fn provision_stream(
    context: &jetstream::Context,
    expected: &stream::Config,
) -> Result<bool, NatsEventsError> {
    if let Ok(stream) = context.get_stream(&expected.name).await {
        let current = stream
            .get_info()
            .await
            .map_err(|_| NatsEventsError::Provision)?
            .config;
        if stream_config_matches_declared(&current, expected) {
            return Ok(false);
        }
        if !safe_stream_update(&current, expected) {
            counter!("rsk_events_nats_provision_total", "status" => "unsafe_drift").increment(1);
            return Err(NatsEventsError::UnsafeDrift);
        }
        let update = stream_config_with_declared_updates(&current, expected);
        context
            .update_stream(update)
            .await
            .map_err(|_| NatsEventsError::Provision)?;
        let actual = context
            .get_stream(&expected.name)
            .await
            .map_err(|_| NatsEventsError::Provision)?
            .get_info()
            .await
            .map_err(|_| NatsEventsError::Provision)?
            .config;
        if !stream_config_matches_declared(&actual, expected) {
            return Err(NatsEventsError::Provision);
        }
        Ok(true)
    } else {
        let stream = context
            .create_stream(expected)
            .await
            .map_err(|_| NatsEventsError::Provision)?;
        if !stream_config_matches_declared(&stream.cached_info().config, expected) {
            return Err(NatsEventsError::Provision);
        }
        Ok(true)
    }
}

async fn provision_consumer(
    stream: &stream::Stream,
    durable_name: &str,
    expected: &pull::Config,
) -> Result<bool, NatsEventsError> {
    let expected_generic = generic_consumer_config(expected);
    if let Ok(existing) = stream.get_consumer::<pull::Config>(durable_name).await {
        let current = existing
            .get_info()
            .await
            .map_err(|_| NatsEventsError::Provision)?
            .config;
        if consumer_config_matches_declared(&current, &expected_generic) {
            return Ok(false);
        }
        if !safe_consumer_update(&current, &expected_generic) {
            counter!("rsk_events_nats_provision_total", "status" => "unsafe_drift").increment(1);
            return Err(NatsEventsError::UnsafeDrift);
        }
        let update = consumer_config_with_declared_updates(&current, &expected_generic);
        let updated = stream
            .create_consumer(update)
            .await
            .map_err(|_| NatsEventsError::Provision)?;
        if !consumer_config_matches_declared(&updated.cached_info().config, &expected_generic) {
            return Err(NatsEventsError::Provision);
        }
        Ok(true)
    } else {
        let created: PullConsumer = stream
            .create_consumer(expected.clone())
            .await
            .map_err(|_| NatsEventsError::Provision)?;
        if !consumer_config_matches_declared(&created.cached_info().config, &expected_generic) {
            return Err(NatsEventsError::Provision);
        }
        Ok(true)
    }
}

fn safe_stream_update(current: &stream::Config, expected: &stream::Config) -> bool {
    subject_set_is_subset(&current.subjects, &expected.subjects)
        && non_decreasing_i64(current.max_bytes, expected.max_bytes)
        && non_decreasing_i64(current.max_messages, expected.max_messages)
        && non_decreasing_i32(current.max_message_size, expected.max_message_size)
        && non_decreasing_i32(current.max_consumers, expected.max_consumers)
        && non_decreasing_duration(current.max_age, expected.max_age)
        && expected.duplicate_window >= current.duplicate_window
        && expected.num_replicas >= current.num_replicas
        && stream_config_matches_declared(
            &stream_config_with_declared_updates(current, expected),
            expected,
        )
}

fn safe_consumer_update(
    current: &async_nats::jetstream::consumer::Config,
    expected: &async_nats::jetstream::consumer::Config,
) -> bool {
    subject_set_is_subset(&current.filter_subjects, &expected.filter_subjects)
        && subject_set_is_subset(&expected.filter_subjects, &current.filter_subjects)
        && expected.ack_wait >= current.ack_wait
        && non_decreasing_i64(current.max_deliver, expected.max_deliver)
        && non_decreasing_i64(current.max_ack_pending, expected.max_ack_pending)
        && non_decreasing_i64(current.max_waiting, expected.max_waiting)
        && non_decreasing_zero_unlimited_i64(current.max_batch, expected.max_batch)
        && non_decreasing_zero_unlimited_i64(current.max_bytes, expected.max_bytes)
        && non_decreasing_duration(current.max_expires, expected.max_expires)
        && expected.num_replicas >= current.num_replicas
        && consumer_config_matches_declared(
            &consumer_config_with_declared_updates(current, expected),
            expected,
        )
}

const fn non_decreasing_i64(current: i64, expected: i64) -> bool {
    if current < 0 {
        expected == current
    } else {
        expected >= current
    }
}

const fn non_decreasing_zero_unlimited_i64(current: i64, expected: i64) -> bool {
    if current == 0 {
        expected == current
    } else {
        non_decreasing_i64(current, expected)
    }
}

const fn non_decreasing_i32(current: i32, expected: i32) -> bool {
    if current < 0 {
        expected == current
    } else {
        expected >= current
    }
}

fn non_decreasing_duration(current: Duration, expected: Duration) -> bool {
    if current.is_zero() {
        expected == current
    } else {
        expected >= current
    }
}

#[cfg(test)]
mod tests {
    use async_nats::jetstream::stream::Republish;
    use time::OffsetDateTime;

    use super::*;

    fn declared_stream() -> stream::Config {
        stream::Config {
            name: "EVENTS".to_owned(),
            subjects: vec!["events.>".to_owned()],
            max_bytes: 10,
            max_messages: 10,
            max_message_size: 10,
            max_consumers: 10,
            max_age: Duration::from_secs(10),
            num_replicas: 1,
            ..Default::default()
        }
    }

    fn declared_consumer() -> async_nats::jetstream::consumer::Config {
        async_nats::jetstream::consumer::Config {
            durable_name: Some("WORKER".to_owned()),
            name: Some("WORKER".to_owned()),
            filter_subjects: vec!["events.>".to_owned()],
            ack_wait: Duration::from_secs(10),
            max_deliver: 3,
            max_ack_pending: 10,
            max_waiting: 10,
            max_batch: 10,
            max_bytes: 10,
            max_expires: Duration::from_secs(10),
            num_replicas: 1,
            ..Default::default()
        }
    }

    #[test]
    fn safe_stream_update_rejects_shortening_unlimited_age() {
        let expected = declared_stream();
        let mut current = expected.clone();
        current.max_age = Duration::ZERO;

        assert!(!safe_stream_update(&current, &expected));
    }

    #[test]
    fn safe_stream_update_rejects_republish_drift() {
        let expected = declared_stream();
        let mut current = expected.clone();
        current.republish = Some(Republish {
            source: "events.>".to_owned(),
            destination: "exfiltrated.>".to_owned(),
            headers_only: false,
        });

        assert!(!safe_stream_update(&current, &expected));
    }

    #[test]
    fn safe_consumer_update_rejects_pause_drift() {
        let expected = declared_consumer();
        let mut current = expected.clone();
        current.pause_until = Some(OffsetDateTime::now_utc());

        assert!(!safe_consumer_update(&current, &expected));
    }

    #[test]
    fn safe_consumer_update_rejects_bounding_unlimited_batch_size() {
        let expected = declared_consumer();
        let mut current = expected.clone();
        current.max_batch = 0;

        assert!(!safe_consumer_update(&current, &expected));
    }

    #[test]
    fn safe_consumer_update_rejects_bounding_unlimited_request_expiry() {
        let expected = declared_consumer();
        let mut current = expected.clone();
        current.max_expires = Duration::ZERO;

        assert!(!safe_consumer_update(&current, &expected));
    }
}
