//! Central logging, trace propagation, OTLP export, and metrics bootstrap.

mod config;
mod redact;

use garde::Validate;
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::{
    KeyValue, global, propagation::TextMapCompositePropagator, trace::TracerProvider as _,
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::SdkTracerProvider,
};
use redact::{RedactingJsonEvent, RedactingJsonFields};
use rsk_config::ExposeSecret;
use thiserror::Error;
use tonic::metadata::{Ascii, MetadataKey, MetadataMap, MetadataValue};
use tracing::Span;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub use config::{LogFormat, OtlpTraceConfig, TelemetryConfig};

/// Installed telemetry providers and operational handles.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    prometheus: Option<PrometheusHandle>,
    service_span: Span,
}

impl TelemetryGuard {
    /// Returns the root span carrying bounded service fields.
    #[must_use]
    pub fn service_span(&self) -> Span {
        self.service_span.clone()
    }

    /// Renders the Prometheus exposition document when metrics are enabled.
    #[must_use]
    pub fn render_prometheus(&self) -> Option<String> {
        self.prometheus.as_ref().map(PrometheusHandle::render)
    }

    /// Forces pending spans to their exporter.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] if the exporter reports a flush failure.
    pub fn force_flush(&self) -> Result<(), TelemetryError> {
        if let Some(provider) = &self.tracer_provider {
            provider
                .force_flush()
                .map_err(|_| TelemetryError::new(TelemetryErrorKind::Flush))?;
        }
        Ok(())
    }

    /// Performs bounded exporter shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] if shutdown cannot finish successfully within
    /// the supplied deadline.
    pub fn shutdown(self, timeout: Duration) -> Result<(), TelemetryError> {
        let Self {
            tracer_provider,
            prometheus: _,
            service_span,
        } = self;
        drop(service_span);
        if let Some(provider) = tracer_provider {
            provider
                .shutdown_with_timeout(timeout)
                .map_err(|_| TelemetryError::new(TelemetryErrorKind::Shutdown))?;
        }
        Ok(())
    }
}

/// Installs the process-global telemetry providers exactly once.
///
/// # Errors
///
/// Returns [`TelemetryError`] for invalid bounded fields, filters, endpoints,
/// exporter metadata, missing Tokio runtime, or an already-installed global
/// subscriber/metrics recorder.
pub fn bootstrap(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    config
        .validate()
        .map_err(|_| TelemetryError::new(TelemetryErrorKind::Field))?;
    validate_config(config)?;
    let filter = EnvFilter::try_new(&config.filter)
        .map_err(|_| TelemetryError::new(TelemetryErrorKind::Filter))?;
    let tracer_provider = config
        .otlp
        .as_ref()
        .map(|otlp| build_tracer_provider(config, otlp))
        .transpose()?;
    let otel_layer = tracer_provider.as_ref().map(|provider| {
        tracing_opentelemetry::layer().with_tracer(provider.tracer(config.service.clone()))
    });
    let subscriber = tracing_subscriber::registry().with(otel_layer).with(filter);
    match config.format {
        LogFormat::Pretty => subscriber
            .with(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(RedactingJsonFields)
                    .with_target(true),
            )
            .try_init(),
        LogFormat::Json => subscriber
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(RedactingJsonEvent)
                    .fmt_fields(RedactingJsonFields),
            )
            .try_init(),
    }
    .map_err(|_| TelemetryError::new(TelemetryErrorKind::Subscriber))?;

    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));

    let prometheus = if config.prometheus {
        Some(
            PrometheusBuilder::new()
                .install_recorder()
                .map_err(|_| TelemetryError::new(TelemetryErrorKind::Metrics))?,
        )
    } else {
        None
    };
    let service_span = tracing::info_span!(
        target: "rsk",
        "service",
        service.name = %config.service,
        service.version = %config.version,
        deployment.environment = %config.environment,
    );
    Ok(TelemetryGuard {
        tracer_provider,
        prometheus,
        service_span,
    })
}

fn build_tracer_provider(
    config: &TelemetryConfig,
    otlp: &OtlpTraceConfig,
) -> Result<SdkTracerProvider, TelemetryError> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(TelemetryError::new(TelemetryErrorKind::Runtime));
    }
    let mut metadata = MetadataMap::new();
    for (name, secret) in &otlp.headers {
        let key: MetadataKey<Ascii> = name
            .parse()
            .map_err(|_| TelemetryError::new(TelemetryErrorKind::Header))?;
        let value: MetadataValue<Ascii> = secret
            .expose_secret()
            .parse()
            .map_err(|_| TelemetryError::new(TelemetryErrorKind::Header))?;
        metadata.insert(key, value);
    }
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(otlp.endpoint.as_str())
        .with_timeout(otlp.timeout)
        .with_metadata(metadata)
        .build()
        .map_err(|_| TelemetryError::new(TelemetryErrorKind::Exporter))?;
    let resource = Resource::builder_empty()
        .with_attributes([
            KeyValue::new("service.name", config.service.clone()),
            KeyValue::new("service.version", config.version.clone()),
            KeyValue::new("deployment.environment.name", config.environment.clone()),
        ])
        .build();
    Ok(SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

fn validate_config(config: &TelemetryConfig) -> Result<(), TelemetryError> {
    if !bounded_name(&config.service, 64)
        || !bounded_name(&config.version, 64)
        || !bounded_name(&config.environment, 32)
    {
        return Err(TelemetryError::new(TelemetryErrorKind::Field));
    }
    if let Some(otlp) = &config.otlp {
        if !matches!(otlp.endpoint.scheme(), "http" | "https")
            || otlp.endpoint.host_str().is_none()
            || otlp.timeout.is_zero()
            || otlp.timeout > Duration::from_secs(30)
            || otlp.headers.len() > 16
        {
            return Err(TelemetryError::new(TelemetryErrorKind::Endpoint));
        }
        for (index, name) in otlp.headers.keys().enumerate() {
            if name.len() > 64
                || otlp
                    .headers
                    .keys()
                    .take(index)
                    .any(|existing| existing.eq_ignore_ascii_case(name))
            {
                return Err(TelemetryError::new(TelemetryErrorKind::Header));
            }
        }
    }
    Ok(())
}

fn bounded_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// A safe telemetry bootstrap failure category.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TelemetryErrorKind {
    /// A service resource field was malformed.
    #[error("invalid telemetry resource field")]
    Field,
    /// The log filter was malformed.
    #[error("invalid telemetry filter")]
    Filter,
    /// The OTLP endpoint or timeout was unsafe.
    #[error("invalid OTLP endpoint configuration")]
    Endpoint,
    /// An OTLP metadata header was malformed or duplicated.
    #[error("invalid OTLP metadata configuration")]
    Header,
    /// OTLP exporter construction failed.
    #[error("OTLP exporter initialization failed")]
    Exporter,
    /// OTLP batch export was requested outside a Tokio runtime.
    #[error("OTLP export requires a Tokio runtime")]
    Runtime,
    /// The global tracing subscriber was already installed.
    #[error("telemetry subscriber installation failed")]
    Subscriber,
    /// The global metrics recorder was already installed.
    #[error("metrics recorder installation failed")]
    Metrics,
    /// A forced exporter flush failed.
    #[error("telemetry exporter flush failed")]
    Flush,
    /// Exporter shutdown failed or exceeded its deadline.
    #[error("telemetry exporter shutdown failed")]
    Shutdown,
}

/// A redacted telemetry bootstrap error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{kind}")]
pub struct TelemetryError {
    kind: TelemetryErrorKind,
}

impl TelemetryError {
    const fn new(kind: TelemetryErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable safe failure category.
    #[must_use]
    pub const fn kind(self) -> TelemetryErrorKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error, process::Command, time::Duration};

    use rsk_config::SecretString;

    use super::*;

    fn base_config() -> TelemetryConfig {
        TelemetryConfig {
            service: "example-api".into(),
            version: "0.1.0".into(),
            environment: "test".into(),
            filter: "info".into(),
            format: LogFormat::Json,
            prometheus: true,
            otlp: None,
        }
    }

    #[test]
    fn production_json_is_bounded_redacted_and_flushes() -> Result<(), Box<dyn Error>> {
        const CHILD: &str = "RSK_TELEMETRY_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            return runtime.block_on(async {
                let mut config = base_config();
                config.otlp = Some(OtlpTraceConfig {
                    endpoint: url::Url::parse("http://127.0.0.1:1")?,
                    timeout: Duration::from_millis(100),
                    headers: BTreeMap::from([(
                        "authorization".into(),
                        SecretString::from("Bearer exporter-secret".to_owned().into_boxed_str()),
                    )]),
                });
                let guard = bootstrap(&config)?;
                {
                    let service_span = guard.service_span();
                    let _service_entered = service_span.enter();
                    let request_span = tracing::info_span!("request");
                    let _request_entered = request_span.enter();
                    let secret =
                        SecretString::from("application-secret".to_owned().into_boxed_str());
                    tracing::info!(
                        request_id = "0198e6f4-ae6f-7a2f-8c12-fd52f2d2a5b1",
                        token = "raw-token-value",
                        cookie = "session=raw-cookie-value",
                        password = "raw-password-value",
                        request_body = "raw-body-value",
                        user_email = "person@example.test",
                        secret_wrapper = ?secret,
                        outcome = "visible-safe-value",
                        "request completed"
                    );
                }
                metrics::counter!("rsk_bootstrap_total").increment(1);
                let rendered = guard.render_prometheus().ok_or("missing metrics handle")?;
                assert!(rendered.contains("rsk_bootstrap_total 1"));
                let flush_error = match guard.force_flush() {
                    Ok(()) => return Err("flush unexpectedly succeeded".into()),
                    Err(error) => error,
                };
                assert_eq!(flush_error.kind(), TelemetryErrorKind::Flush);
                guard.shutdown(Duration::from_secs(1))?;
                Ok(())
            });
        }

        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::production_json_is_bounded_redacted_and_flushes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()?;
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "child telemetry test failed: {logs}"
        );
        assert!(logs.contains("\"service.name\":\"example-api\""));
        assert!(logs.contains("\"request_id\":\"0198e6f4-ae6f-7a2f-8c12-fd52f2d2a5b1\""));
        assert!(logs.contains("[REDACTED]"));
        assert!(!logs.contains("application-secret"));
        assert!(!logs.contains("exporter-secret"));
        for forbidden in [
            "raw-token-value",
            "raw-cookie-value",
            "raw-password-value",
            "raw-body-value",
            "person@example.test",
        ] {
            assert!(
                !logs.contains(forbidden),
                "forbidden value leaked: {forbidden}; logs: {logs}"
            );
        }
        assert!(logs.contains("visible-safe-value"));
        Ok(())
    }

    #[test]
    fn rejects_case_insensitive_duplicate_headers() -> Result<(), Box<dyn Error>> {
        let mut config = base_config();
        config.prometheus = false;
        config.otlp = Some(OtlpTraceConfig {
            endpoint: url::Url::parse("https://collector.example.test")?,
            timeout: Duration::from_secs(1),
            headers: BTreeMap::from([
                (
                    "authorization".into(),
                    SecretString::from("one".to_owned().into_boxed_str()),
                ),
                (
                    "Authorization".into(),
                    SecretString::from("two".to_owned().into_boxed_str()),
                ),
            ]),
        });
        let error = match validate_config(&config) {
            Ok(()) => return Err("duplicate headers were accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), TelemetryErrorKind::Header);
        Ok(())
    }
}
