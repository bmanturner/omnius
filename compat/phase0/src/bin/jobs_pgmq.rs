//! Exercises embedded PGMQ installation and a durable message lifecycle.

use std::io;

use pgmq::PGMQueueExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;

const QUEUE: &str = "phase0_jobs";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProbeJob {
    value: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("PGMQ_DATABASE_URL").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PGMQ_DATABASE_URL is required: {error}"),
        )
    })?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?;
    let queue = PGMQueueExt::new_with_pool(pool.clone()).await;
    queue.install_sql_from_embedded().await?;
    queue.create(QUEUE).await?;

    let sent_id = queue.send(QUEUE, &ProbeJob { value: 42 }).await?;
    let received = queue
        .read::<ProbeJob>(QUEUE, 30_i32)
        .await?
        .ok_or_else(|| io::Error::other("PGMQ did not return the enqueued message"))?;
    if received.msg_id != sent_id || received.message != (ProbeJob { value: 42 }) {
        return Err(io::Error::other("PGMQ changed message identity or payload").into());
    }
    if !queue.archive(QUEUE, received.msg_id).await? {
        return Err(io::Error::other("PGMQ did not archive the message").into());
    }
    queue.drop_queue(QUEUE).await?;
    pool.close().await;
    println!("PGMQ install, enqueue, read, archive, and cleanup succeeded");
    Ok(())
}
