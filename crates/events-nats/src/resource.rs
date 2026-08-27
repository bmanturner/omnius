use async_nats::jetstream::{
    consumer::{self, AckPolicy, DeliverPolicy, IntoConsumerConfig as _, ReplayPolicy, pull},
    stream::{self, DiscardPolicy, RetentionPolicy, StorageType},
};

use crate::{
    config::{
        NatsConsumerConfig, NatsDeliveryConfig, NatsDiscardPolicy, NatsEventsConfig,
        NatsRetentionPolicy, NatsStorage, NatsStreamConfig,
    },
    error::NatsEventsError,
};

const MAIN_DESCRIPTION: &str = "omnius durable domain events";
const DLQ_DESCRIPTION: &str = "omnius durable event dead letters";
const CONSUMER_DESCRIPTION: &str = "omnius durable event handler";

pub(crate) fn stream_config(
    declared: &NatsStreamConfig,
    dlq: bool,
) -> Result<stream::Config, NatsEventsError> {
    Ok(stream::Config {
        name: declared.name.clone(),
        max_bytes: i64::try_from(declared.max_bytes).map_err(|_| NatsEventsError::Config)?,
        max_messages: i64::try_from(declared.max_messages).map_err(|_| NatsEventsError::Config)?,
        max_messages_per_subject: -1,
        discard: match declared.discard {
            NatsDiscardPolicy::Old => DiscardPolicy::Old,
            NatsDiscardPolicy::New => DiscardPolicy::New,
        },
        discard_new_per_subject: false,
        subjects: declared.subjects.clone(),
        retention: match declared.retention {
            NatsRetentionPolicy::Limits => RetentionPolicy::Limits,
            NatsRetentionPolicy::Interest => RetentionPolicy::Interest,
        },
        max_consumers: i32::try_from(declared.max_consumers)
            .map_err(|_| NatsEventsError::Config)?,
        max_age: declared.max_age,
        max_message_size: i32::try_from(declared.max_message_size)
            .map_err(|_| NatsEventsError::Config)?,
        storage: match declared.storage {
            NatsStorage::File => StorageType::File,
            NatsStorage::Memory => StorageType::Memory,
        },
        num_replicas: declared.replicas,
        no_ack: false,
        duplicate_window: declared.duplicate_window,
        description: Some(if dlq {
            DLQ_DESCRIPTION.to_owned()
        } else {
            MAIN_DESCRIPTION.to_owned()
        }),
        sealed: false,
        deny_delete: true,
        deny_purge: true,
        allow_rollup: false,
        allow_direct: false,
        mirror_direct: false,
        ..Default::default()
    })
}

pub(crate) fn pull_consumer_config(
    consumer: &NatsConsumerConfig,
    delivery: &NatsDeliveryConfig,
    replicas: usize,
) -> Result<pull::Config, NatsEventsError> {
    Ok(pull::Config {
        durable_name: Some(consumer.durable_name.clone()),
        name: Some(consumer.durable_name.clone()),
        description: Some(CONSUMER_DESCRIPTION.to_owned()),
        deliver_policy: DeliverPolicy::All,
        ack_policy: AckPolicy::Explicit,
        ack_wait: consumer.ack_wait,
        max_deliver: i64::from(consumer.max_deliveries),
        filter_subject: String::new(),
        filter_subjects: consumer.filter_subjects.clone(),
        replay_policy: ReplayPolicy::Instant,
        rate_limit: 0,
        sample_frequency: 0,
        max_waiting: i64::try_from(consumer.max_ack_pending)
            .map_err(|_| NatsEventsError::Config)?,
        max_ack_pending: i64::try_from(consumer.max_ack_pending)
            .map_err(|_| NatsEventsError::Config)?,
        headers_only: false,
        max_batch: i64::try_from(delivery.pull_batch).map_err(|_| NatsEventsError::Config)?,
        max_bytes: i64::try_from(delivery.pull_max_bytes).map_err(|_| NatsEventsError::Config)?,
        max_expires: delivery.pull_expiry,
        inactive_threshold: std::time::Duration::ZERO,
        num_replicas: replicas,
        memory_storage: false,
        backoff: Vec::new(),
        ..Default::default()
    })
}

pub(crate) fn generic_consumer_config(config: &pull::Config) -> consumer::Config {
    config.into_consumer_config()
}

pub(crate) fn stream_config_matches_declared(
    actual: &stream::Config,
    declared: &stream::Config,
) -> bool {
    let mut actual = actual.clone();
    let mut declared = declared.clone();
    actual.subjects.sort_unstable();
    declared.subjects.sort_unstable();
    actual.metadata.clone_from(&declared.metadata);
    if compression_disabled(actual.compression.as_ref())
        && compression_disabled(declared.compression.as_ref())
    {
        actual.compression.clone_from(&declared.compression);
    }
    actual == declared
}

fn compression_disabled(compression: Option<&stream::Compression>) -> bool {
    compression.is_none_or(|value| *value == stream::Compression::None)
}

pub(crate) fn stream_config_with_declared_updates(
    current: &stream::Config,
    declared: &stream::Config,
) -> stream::Config {
    let mut updated = current.clone();
    updated.subjects.clone_from(&declared.subjects);
    updated.max_messages = declared.max_messages;
    updated.max_bytes = declared.max_bytes;
    updated.max_message_size = declared.max_message_size;
    updated.max_consumers = declared.max_consumers;
    updated.max_age = declared.max_age;
    updated.duplicate_window = declared.duplicate_window;
    updated.num_replicas = declared.num_replicas;
    updated
}

pub(crate) fn consumer_config_matches_declared(
    actual: &consumer::Config,
    declared: &consumer::Config,
) -> bool {
    let mut actual = actual.clone();
    let mut declared = declared.clone();
    actual.filter_subjects.sort_unstable();
    declared.filter_subjects.sort_unstable();
    actual.metadata.clone_from(&declared.metadata);
    actual == declared
}

pub(crate) fn consumer_config_with_declared_updates(
    current: &consumer::Config,
    declared: &consumer::Config,
) -> consumer::Config {
    let mut updated = current.clone();
    updated.ack_wait = declared.ack_wait;
    updated.max_deliver = declared.max_deliver;
    updated.max_ack_pending = declared.max_ack_pending;
    updated.max_waiting = declared.max_waiting;
    updated.max_batch = declared.max_batch;
    updated.max_bytes = declared.max_bytes;
    updated.max_expires = declared.max_expires;
    updated.num_replicas = declared.num_replicas;
    updated
}

pub(crate) fn subject_set_is_subset(subjects: &[String], superset: &[String]) -> bool {
    subjects.iter().all(|subject| superset.contains(subject))
}

pub(crate) fn expected_resources(
    config: &NatsEventsConfig,
) -> Result<(stream::Config, stream::Config, pull::Config), NatsEventsError> {
    Ok((
        stream_config(&config.stream, false)?,
        stream_config(&config.dlq.stream, true)?,
        pull_consumer_config(&config.consumer, &config.delivery, config.stream.replicas)?,
    ))
}

#[cfg(test)]
mod tests {
    use async_nats::jetstream::stream::{Republish, Source, SubjectTransform};
    use time::OffsetDateTime;

    use super::*;

    fn declared_stream() -> stream::Config {
        stream::Config {
            name: "EVENTS".to_owned(),
            subjects: vec!["events.>".to_owned()],
            ..Default::default()
        }
    }

    fn declared_consumer() -> consumer::Config {
        consumer::Config {
            durable_name: Some("WORKER".to_owned()),
            name: Some("WORKER".to_owned()),
            filter_subjects: vec!["events.>".to_owned()],
            ..Default::default()
        }
    }

    #[test]
    fn stream_match_rejects_republish_drift() {
        let declared = declared_stream();
        let mut actual = declared.clone();
        actual.republish = Some(Republish {
            source: "events.>".to_owned(),
            destination: "exfiltrated.>".to_owned(),
            headers_only: false,
        });

        assert!(!stream_config_matches_declared(&actual, &declared));
    }

    #[test]
    fn stream_match_rejects_mirror_drift() {
        let declared = declared_stream();
        let mut actual = declared.clone();
        actual.mirror = Some(Source {
            name: "EXTERNAL".to_owned(),
            ..Default::default()
        });

        assert!(!stream_config_matches_declared(&actual, &declared));
    }

    #[test]
    fn stream_match_rejects_sources_drift() {
        let declared = declared_stream();
        let mut actual = declared.clone();
        actual.sources = Some(vec![Source {
            name: "EXTERNAL".to_owned(),
            ..Default::default()
        }]);

        assert!(!stream_config_matches_declared(&actual, &declared));
    }

    #[test]
    fn stream_match_rejects_subject_transform_drift() {
        let declared = declared_stream();
        let mut actual = declared.clone();
        actual.subject_transform = Some(SubjectTransform {
            source: "events.>".to_owned(),
            destination: "redirected.>".to_owned(),
        });

        assert!(!stream_config_matches_declared(&actual, &declared));
    }

    #[test]
    fn consumer_match_rejects_pause_drift() {
        let declared = declared_consumer();
        let mut actual = declared.clone();
        actual.pause_until = Some(OffsetDateTime::now_utc());

        assert!(!consumer_config_matches_declared(&actual, &declared));
    }

    #[test]
    fn consumer_match_rejects_delivery_subject_drift() {
        let declared = declared_consumer();
        let mut actual = declared.clone();
        actual.deliver_subject = Some("redirected".to_owned());

        assert!(!consumer_config_matches_declared(&actual, &declared));
    }
}
