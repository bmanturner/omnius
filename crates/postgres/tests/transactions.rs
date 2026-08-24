//! Real PostgreSQL transaction replay and exclusion contracts.

use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, PostgresTransactionRunner, TransactionIsolation,
    TransactionRetryConfig, TransactionRunError,
};
use rsk_test_support::PostgresFixture;
use tokio::sync::Barrier;

fn retry_config(max_attempts: u8) -> TransactionRetryConfig {
    TransactionRetryConfig {
        max_attempts,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
        max_jitter: Duration::ZERO,
        isolation: TransactionIsolation::Serializable,
    }
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-transaction-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: retry_config(3),
    }
}

#[tokio::test]
async fn serializable_conflict_replays_the_complete_transaction() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "CREATE TABLE transaction_counter (id integer PRIMARY KEY, value integer NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query("INSERT INTO transaction_counter (id, value) VALUES (1, 0)")
        .execute(&mut *connection)
        .await?;
    drop(connection);

    let runner = PostgresTransactionRunner::new(pool.clone(), retry_config(3))?;
    let barrier = Arc::new(Barrier::new(2));
    let left_attempts = Arc::new(AtomicUsize::new(0));
    let right_attempts = Arc::new(AtomicUsize::new(0));
    let left_barrier = Arc::clone(&barrier);
    let right_barrier = Arc::clone(&barrier);
    let left_count = Arc::clone(&left_attempts);
    let right_count = Arc::clone(&right_attempts);

    let left = runner.run_repeatable("serialization_probe", async move |connection| {
        let attempt = left_count.fetch_add(1, Ordering::Relaxed);
        let value: i32 = sqlx::query_scalar("SELECT value FROM transaction_counter WHERE id = 1")
            .fetch_one(&mut *connection)
            .await?;
        if attempt == 0 {
            left_barrier.wait().await;
        }
        sqlx::query("UPDATE transaction_counter SET value = $1 WHERE id = 1")
            .bind(value + 1)
            .execute(&mut *connection)
            .await?;
        Ok::<(), sqlx::Error>(())
    });
    let right = runner.run_repeatable("serialization_probe", async move |connection| {
        let attempt = right_count.fetch_add(1, Ordering::Relaxed);
        let value: i32 = sqlx::query_scalar("SELECT value FROM transaction_counter WHERE id = 1")
            .fetch_one(&mut *connection)
            .await?;
        if attempt == 0 {
            right_barrier.wait().await;
        }
        sqlx::query("UPDATE transaction_counter SET value = $1 WHERE id = 1")
            .bind(value + 1)
            .execute(&mut *connection)
            .await?;
        Ok::<(), sqlx::Error>(())
    });
    let (left_result, right_result) = tokio::join!(left, right);
    left_result?;
    right_result?;

    let mut connection = pool.acquire().await?;
    let final_value: i32 = sqlx::query_scalar("SELECT value FROM transaction_counter WHERE id = 1")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(final_value, 2);
    assert_eq!(
        left_attempts.load(Ordering::Relaxed) + right_attempts.load(Ordering::Relaxed),
        3
    );
    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn constraint_failures_are_not_retried_and_transient_exhaustion_is_exact()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let mut connection = pool.acquire().await?;
    sqlx::query("CREATE TABLE transaction_unique (id integer PRIMARY KEY)")
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO transaction_unique (id) VALUES (1)")
        .execute(&mut *connection)
        .await?;
    drop(connection);

    let runner = PostgresTransactionRunner::new(pool.clone(), retry_config(3))?;
    let constraint_attempts = Arc::new(AtomicUsize::new(0));
    let constraint_count = Arc::clone(&constraint_attempts);
    let constraint = runner
        .run_repeatable("constraint_probe", async move |connection| {
            constraint_count.fetch_add(1, Ordering::Relaxed);
            sqlx::query("INSERT INTO transaction_unique (id) VALUES (1)")
                .execute(&mut *connection)
                .await?;
            Ok::<(), sqlx::Error>(())
        })
        .await;
    assert!(matches!(constraint, Err(TransactionRunError::Operation(_))));
    assert_eq!(constraint_attempts.load(Ordering::Relaxed), 1);

    let transient_attempts = Arc::new(AtomicUsize::new(0));
    let transient_count = Arc::clone(&transient_attempts);
    let exhausted = runner
        .run_repeatable("exhaustion_probe", async move |connection| {
            transient_count.fetch_add(1, Ordering::Relaxed);
            sqlx::query(
                "DO $$ BEGIN RAISE EXCEPTION 'forced serialization' USING ERRCODE = '40001'; END $$",
            )
            .execute(&mut *connection)
            .await?;
            Ok::<(), sqlx::Error>(())
        })
        .await;
    assert!(matches!(
        exhausted,
        Err(TransactionRunError::RetryExhausted { attempts: 3, .. })
    ));
    assert_eq!(transient_attempts.load(Ordering::Relaxed), 3);

    let deadlock_attempts = Arc::new(AtomicUsize::new(0));
    let deadlock_count = Arc::clone(&deadlock_attempts);
    let deadlock_exhausted = runner
        .run_repeatable("deadlock_probe", async move |connection| {
            deadlock_count.fetch_add(1, Ordering::Relaxed);
            sqlx::query(
                "DO $$ BEGIN RAISE EXCEPTION 'forced deadlock' USING ERRCODE = '40P01'; END $$",
            )
            .execute(&mut *connection)
            .await?;
            Ok::<(), sqlx::Error>(())
        })
        .await;
    assert!(matches!(
        deadlock_exhausted,
        Err(TransactionRunError::RetryExhausted { attempts: 3, .. })
    ));
    assert_eq!(deadlock_attempts.load(Ordering::Relaxed), 3);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
