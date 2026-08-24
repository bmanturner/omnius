//! Redis configuration, secret-redaction, TLS, namespace, and bound contracts.

use std::time::Duration;

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_redis_core::{RedisConfig, RedisConfigError};

fn enabled(url: &str) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(SecretString::from(url.to_owned())),
        ..RedisConfig::default()
    }
}

#[test]
fn disabled_configuration_is_explicit_and_may_omit_url() {
    let config = RedisConfig::default();
    assert!(!config.enabled);
    assert_eq!(
        config.validate_for(DeploymentEnvironment::Production),
        Ok(())
    );
}

#[test]
fn enabled_configuration_requires_valid_url_and_safe_bounds() {
    let mut config = RedisConfig {
        enabled: true,
        ..RedisConfig::default()
    };
    assert_eq!(
        config.validate_for(DeploymentEnvironment::Development),
        Err(RedisConfigError::MissingUrl)
    );

    config.url = Some(SecretString::from("not a redis url".to_owned()));
    assert_eq!(
        config.validate_for(DeploymentEnvironment::Development),
        Err(RedisConfigError::InvalidUrl)
    );

    config = enabled("redis://localhost:6379/0");
    config.health_timeout = Duration::from_millis(1);
    assert_eq!(
        config.validate_for(DeploymentEnvironment::Development),
        Err(RedisConfigError::HealthBeforeCommand)
    );

    config = enabled("redis://localhost:6379/0");
    config.reconnect.max_retries = 0;
    assert_eq!(
        config.validate_for(DeploymentEnvironment::Development),
        Err(RedisConfigError::InvalidReconnect)
    );
}

#[test]
fn production_requires_verified_tls_and_authentication() {
    assert_eq!(
        enabled("redis://default:secret@example.com:6379/0")
            .validate_for(DeploymentEnvironment::Production),
        Err(RedisConfigError::ProductionTlsRequired)
    );
    assert_eq!(
        enabled("rediss://example.com:6379/0").validate_for(DeploymentEnvironment::Production),
        Err(RedisConfigError::ProductionAuthenticationRequired)
    );
    assert_eq!(
        enabled("rediss://default:@example.com:6379/0")
            .validate_for(DeploymentEnvironment::Production),
        Err(RedisConfigError::ProductionAuthenticationRequired)
    );
    assert_eq!(
        enabled("rediss://default:secret@example.com:6379/0")
            .validate_for(DeploymentEnvironment::Production),
        Ok(())
    );
}

#[test]
fn debug_and_errors_never_render_credentials() {
    let secret = "redis://default:do-not-log@example.com:6379/0";
    let config = enabled(secret);
    let debug = format!("{config:?}");
    assert!(!debug.contains("do-not-log"));
    assert!(!debug.contains(secret));
    assert!(debug.contains("url_configured"));
}

#[test]
fn versioned_keys_and_value_limit_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = RedisConfig {
        key_prefix: "billing".to_owned(),
        schema_version: "v3".to_owned(),
        ..RedisConfig::default()
    };
    assert_eq!(
        config.key(&["tenant-1", "invoice-2"])?,
        "billing:v3:tenant-1:invoice-2"
    );
    assert_eq!(config.key(&[]), Err(RedisConfigError::InvalidKey));
    assert_eq!(
        config.key(&["bad:component"]),
        Err(RedisConfigError::InvalidKey)
    );

    config.max_value_bytes = 0;
    assert_eq!(
        config.validate_for(DeploymentEnvironment::Test),
        Err(RedisConfigError::InvalidValueLimit)
    );
    Ok(())
}

#[test]
fn serde_rejects_unknown_configuration_fields() {
    let parsed = toml::from_str::<RedisConfig>(
        r"
        enabled = false
        unexpected = true
        ",
    );
    assert!(parsed.is_err());
}
