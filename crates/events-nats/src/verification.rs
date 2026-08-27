use async_nats::jetstream::{
    self,
    consumer::{PullConsumer, pull},
    stream,
};
use metrics::counter;

use crate::{
    error::NatsEventsError,
    resource::{
        consumer_config_matches_declared, generic_consumer_config, stream_config_matches_declared,
    },
};

pub(crate) async fn verify_stream(
    context: &jetstream::Context,
    expected: &stream::Config,
) -> Result<stream::Stream, NatsEventsError> {
    let stream = context
        .get_stream(&expected.name)
        .await
        .map_err(|_| NatsEventsError::Access)?;
    let actual = stream
        .get_info()
        .await
        .map_err(|_| NatsEventsError::Access)?;
    if !stream_config_matches_declared(&actual.config, expected) {
        counter!("omnius_events_nats_verification_total", "status" => "drift").increment(1);
        return Err(NatsEventsError::Drift);
    }
    Ok(stream)
}

pub(crate) async fn verify_consumer(
    stream: &stream::Stream,
    durable_name: &str,
    expected: &pull::Config,
) -> Result<PullConsumer, NatsEventsError> {
    let consumer = stream
        .get_consumer::<pull::Config>(durable_name)
        .await
        .map_err(|_| NatsEventsError::Access)?;
    let actual = consumer
        .get_info()
        .await
        .map_err(|_| NatsEventsError::Access)?;
    if !consumer_config_matches_declared(&actual.config, &generic_consumer_config(expected)) {
        counter!("omnius_events_nats_verification_total", "status" => "drift").increment(1);
        return Err(NatsEventsError::Drift);
    }
    Ok(consumer)
}
