use async_nats::{
    Client, ConnectOptions,
    jetstream::{self, context::ContextBuilder},
};
use rsk_config::{DeploymentEnvironment, ExposeSecret as _};

use crate::{
    config::{NatsAuthConfig, NatsConnectionConfig},
    error::NatsEventsError,
};

pub(crate) struct ConnectedNats {
    pub(crate) client: Client,
    pub(crate) jetstream: jetstream::Context,
}

pub(crate) async fn connect(
    config: &NatsConnectionConfig,
    environment: DeploymentEnvironment,
) -> Result<ConnectedNats, NatsEventsError> {
    config.validate_for(environment)?;

    let mut options = match &config.auth {
        NatsAuthConfig::CredentialsFile { path } => ConnectOptions::new()
            .credentials_file(path)
            .await
            .map_err(|_| NatsEventsError::Connect)?,
        NatsAuthConfig::UserPassword { username, password } => ConnectOptions::new()
            .user_and_password(
                username.expose_secret().to_owned(),
                password.expose_secret().to_owned(),
            ),
    };
    options = options
        .name("rsk-events-nats")
        .require_tls(config.tls_required)
        .connection_timeout(config.connection_timeout)
        .request_timeout(Some(config.operation_timeout))
        .client_capacity(config.client_capacity)
        .subscription_capacity(config.subscription_capacity)
        .max_reconnects(Some(config.max_reconnects))
        .ignore_discovered_servers();
    for certificate in &config.root_certificates {
        options = options.add_root_certificates(certificate.clone());
    }

    let client = options
        .connect(config.url.expose_secret())
        .await
        .map_err(|_| NatsEventsError::Connect)?;
    let jetstream = ContextBuilder::new()
        .timeout(config.operation_timeout)
        .ack_timeout(config.operation_timeout)
        .max_ack_inflight(config.client_capacity)
        .backpressure_on_inflight(true)
        .concurrency_limit(Some(config.client_capacity.min(256)))
        .build(client.clone());
    Ok(ConnectedNats { client, jetstream })
}
