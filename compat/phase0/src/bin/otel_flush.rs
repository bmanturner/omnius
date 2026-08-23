//! Proves checked OpenTelemetry flush and bounded shutdown behavior.

use std::{io, time::Duration};

use opentelemetry::trace::{Tracer, TracerProvider as _};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://127.0.0.1:1")
        .with_timeout(Duration::from_millis(200))
        .build()?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("phase0-flush-spike");
    tracer.in_span("expected-export-failure", |_| {});

    if provider.force_flush().is_ok() {
        return Err(
            io::Error::other("flush unexpectedly succeeded against a closed endpoint").into(),
        );
    }
    provider.shutdown_with_timeout(Duration::from_secs(1))?;
    println!("force_flush reported export failure; bounded shutdown completed");
    Ok(())
}
