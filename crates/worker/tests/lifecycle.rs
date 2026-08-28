//! Worker readiness-first drain lifecycle contracts.

use std::{error::Error, sync::Arc, time::Duration};

use omnius_core::{
    BuildMetadata, BuildMetadataInput, ErrorCode, SchemaCompatibility, ServiceError,
};
use omnius_health::{HealthBuilder, HealthConfig};
use omnius_runtime::{Criticality, TaskSpec, TaskStatus};
use omnius_worker::WorkerBuilder;
use tokio::sync::{Mutex, oneshot};

fn metadata() -> Result<BuildMetadata, Box<dyn Error>> {
    Ok(BuildMetadata::current(BuildMetadataInput {
        service: "worker-drain-test",
        profile: "worker",
        modules: &["runtime", "health", "jobs"],
        schema: SchemaCompatibility {
            minimum: "0",
            maximum: "0",
        },
    })?)
}

#[tokio::test]
async fn drain_marks_unready_stops_new_leases_and_finishes_active_work()
-> Result<(), Box<dyn Error>> {
    let health = HealthBuilder::new(metadata()?, HealthConfig::default())?.build();
    let health_probe = health.clone();
    let (leased_tx, leased_rx) = oneshot::channel();
    let leased_tx = Arc::new(Mutex::new(Some(leased_tx)));
    let (complete_tx, complete_rx) = oneshot::channel();
    let complete_rx = Arc::new(Mutex::new(Some(complete_rx)));
    let leases = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let task_leases = Arc::clone(&leases);
    let mut builder = WorkerBuilder::new(health)?;
    builder.register_task(TaskSpec::new(
        "cooperative-job-worker",
        "jobs",
        Criticality::Required,
        Duration::from_secs(1),
        move |context| {
            let leased_tx = Arc::clone(&leased_tx);
            let complete_rx = Arc::clone(&complete_rx);
            let task_leases = Arc::clone(&task_leases);
            async move {
                task_leases.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(sender) = leased_tx.lock().await.take() {
                    let _ = sender.send(());
                }
                context.draining().await;
                if let Some(receiver) = complete_rx.lock().await.take() {
                    let _ = receiver.await;
                }
                Ok(())
            }
        },
    ))?;
    let runtime = builder.start()?;
    leased_rx.await?;
    assert!(health_probe.is_ready());

    runtime.begin_drain();
    assert!(!health_probe.is_ready());
    assert_eq!(leases.load(std::sync::atomic::Ordering::SeqCst), 1);
    let _ = complete_tx.send(());
    let report = runtime.shutdown().await;

    assert!(report.forced.is_empty());
    assert_eq!(leases.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        report
            .snapshots
            .iter()
            .find(|snapshot| snapshot.name == "cooperative-job-worker")
            .map(|snapshot| snapshot.status),
        Some(TaskStatus::Exited)
    );
    Ok(())
}

#[tokio::test]
async fn required_failure_marks_readiness_false_before_supervisor_shutdown()
-> Result<(), Box<dyn Error>> {
    let health = HealthBuilder::new(metadata()?, HealthConfig::default())?.build();
    let health_probe = health.clone();
    let code = ErrorCode::try_new("WORKER_REQUIRED_TASK_FAILED")?;
    let mut builder = WorkerBuilder::new(health)?;
    builder.register_task(TaskSpec::new(
        "required-failure",
        "jobs",
        Criticality::Required,
        Duration::from_secs(1),
        move |_| async move { Err(ServiceError::new(code, "required worker task failed")) },
    ))?;
    let runtime = builder.start()?;

    tokio::time::timeout(Duration::from_millis(100), async {
        while health_probe.is_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(!health_probe.is_ready());
    let report = runtime.shutdown().await;
    assert!(report.fatal);
    Ok(())
}
