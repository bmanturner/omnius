use std::{collections::BTreeMap, time::Duration};

use garde::Validate;
use omnius_config::SecretString;
use serde::Deserialize;
use url::Url;

/// Encoding used by the local tracing formatter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    /// Human-readable local output.
    Pretty,
    /// Structured production JSON output.
    Json,
}

/// Optional OTLP trace export configuration.
#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OtlpTraceConfig {
    /// Collector gRPC endpoint.
    #[garde(skip)]
    pub endpoint: Url,
    /// Export request deadline.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub timeout: Duration,
    /// Secret gRPC metadata values keyed by an allowlisted header name.
    #[garde(skip)]
    pub headers: BTreeMap<String, SecretString>,
}

/// Logging, tracing, and metrics bootstrap settings.
#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TelemetryConfig {
    /// Stable service name attached to telemetry resources.
    #[garde(ascii, length(min = 1, max = 64))]
    pub service: String,
    /// Application version attached to telemetry resources.
    #[garde(ascii, length(min = 1, max = 64))]
    pub version: String,
    /// Bounded deployment environment name.
    #[garde(ascii, length(min = 1, max = 32))]
    pub environment: String,
    /// `tracing-subscriber` filter expression.
    #[garde(ascii, length(min = 1, max = 512))]
    pub filter: String,
    /// Log output encoding.
    #[garde(skip)]
    pub format: LogFormat,
    /// Install the Prometheus metrics recorder.
    #[garde(skip)]
    pub prometheus: bool,
    /// Optional OTLP trace exporter.
    #[garde(dive)]
    pub otlp: Option<OtlpTraceConfig>,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, time::Duration};

    use garde::Validate;
    use serde_json::json;

    use super::{LogFormat, TelemetryConfig};

    fn config_json() -> serde_json::Value {
        json!({
            "service": "example-api",
            "version": "0.1.0",
            "environment": "test",
            "filter": "info",
            "format": "json",
            "prometheus": false,
            "otlp": {
                "endpoint": "http://collector:4317",
                "timeout": "1500ms",
                "headers": {}
            }
        })
    }

    #[test]
    fn deserializes_kebab_case_format_and_human_durations() -> Result<(), Box<dyn Error>> {
        let config: TelemetryConfig = serde_json::from_value(config_json())?;
        assert_eq!(config.format, LogFormat::Json);
        let otlp = config.otlp.ok_or("otlp section must deserialize")?;
        assert_eq!(otlp.timeout, Duration::from_millis(1500));
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        let mut top = config_json();
        top["extra"] = json!(true);
        assert!(serde_json::from_value::<TelemetryConfig>(top).is_err());

        let mut nested = config_json();
        nested["otlp"]["extra"] = json!(true);
        assert!(serde_json::from_value::<TelemetryConfig>(nested).is_err());
    }

    #[test]
    fn field_bounds_reject_empty_oversized_and_non_ascii_values() -> Result<(), Box<dyn Error>> {
        let valid: TelemetryConfig = serde_json::from_value(config_json())?;
        valid.validate().map_err(|error| error.to_string())?;

        for (field, value) in [
            ("service", String::new()),
            ("service", "s".repeat(65)),
            ("version", "v".repeat(65)),
            ("environment", "e".repeat(33)),
            ("filter", "f".repeat(513)),
            ("service", "café".to_owned()),
        ] {
            let mut document = config_json();
            document[field] = json!(value);
            let config: TelemetryConfig = serde_json::from_value(document)?;
            assert!(config.validate().is_err(), "{field} = {value:?} must fail");
        }

        let mut at_limit = config_json();
        at_limit["service"] = json!("s".repeat(64));
        at_limit["filter"] = json!("f".repeat(512));
        let config: TelemetryConfig = serde_json::from_value(at_limit)?;
        config.validate().map_err(|error| error.to_string())?;
        Ok(())
    }
}
