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
