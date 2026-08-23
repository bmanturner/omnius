//! Exercises enqueue, processing, and bounded drain with Apalis Redis.

use std::{
    io,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use apalis::prelude::*;
use apalis_redis::RedisStorage;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

static PROCESSED: AtomicUsize = AtomicUsize::new(0);
static COMPLETED: LazyLock<Notify> = LazyLock::new(Notify::new);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProbeJob {
    value: u64,
}

async fn process(job: ProbeJob) -> Result<(), io::Error> {
    if job.value != 42 {
        return Err(io::Error::other("unexpected job payload"));
    }
    PROCESSED.fetch_add(1, Ordering::SeqCst);
    COMPLETED.notify_one();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let redis_url = std::env::var("APALIS_REDIS_URL").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("APALIS_REDIS_URL is required: {error}"),
        )
    })?;
    let connection = apalis_redis::connect(redis_url).await?;
    let mut storage = RedisStorage::new(connection);
    storage.push(ProbeJob { value: 42 }).await?;

    let worker = WorkerBuilder::new("phase0-apalis")
        .backend(storage)
        .build_fn(process);
    let signal = async {
        tokio::time::timeout(Duration::from_secs(5), COMPLETED.notified())
            .await
            .map_err(io::Error::other)?;
        Ok(())
    };
    Monitor::new()
        .register(worker)
        .with_terminator(tokio::time::sleep(Duration::from_secs(2)))
        .run_with_signal(signal)
        .await?;

    if PROCESSED.load(Ordering::SeqCst) != 1 {
        return Err(io::Error::other("job was not processed exactly once").into());
    }
    println!("Apalis Redis enqueue, processing, and drain succeeded");
    Ok(())
}
