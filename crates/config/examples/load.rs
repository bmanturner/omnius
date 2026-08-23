//! Loads the checked-in redacted configuration reference.

use std::error::Error;

use garde::Validate;
use rsk_config::{ConfigLoader, DeploymentEnvironment, ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct ApplicationConfig {
    #[garde(dive)]
    service: ServiceConfig,
}

#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    #[garde(ascii, length(min = 1, max = 32))]
    environment: String,
    #[garde(ip)]
    listen_address: String,
    #[garde(range(min = 1, max = 65_535))]
    port: u16,
    #[garde(skip)]
    api_token: SecretString,
}

fn main() -> Result<(), Box<dyn Error>> {
    let loaded = ConfigLoader::new("EXAMPLE", DeploymentEnvironment::Development)?
        .with_base_file("config/reference.toml")
        .load::<ApplicationConfig>()?;
    let config = loaded.value();
    println!(
        "environment={} listen={}:{} token_present={} layers={}",
        config.service.environment,
        config.service.listen_address,
        config.service.port,
        !config.service.api_token.expose_secret().is_empty(),
        loaded.layers().len()
    );
    Ok(())
}
