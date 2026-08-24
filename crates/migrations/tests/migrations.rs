//! Real PostgreSQL migration command and rolling compatibility contracts.

use std::{
    error::Error,
    fs,
    path::Path,
    time::{Duration, Instant},
};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{
    MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationError, MigrationRunner,
    SchemaVersionRange,
};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{CleanDirectory, PostgresFixture};
use sqlx::migrate::Migrator;

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-migrations-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

fn migration_config(run_on_startup: bool) -> MigrationConfig {
    MigrationConfig {
        run_on_startup,
        operation_timeout: Duration::from_secs(10),
    }
}

fn write_migrations(directory: &Path, migrations: &[(&str, &str)]) -> Result<(), Box<dyn Error>> {
    for (name, sql) in migrations {
        fs::write(directory.join(name), sql)?;
    }
    Ok(())
}

async fn pool(fixture: &PostgresFixture) -> Result<PostgresPool, Box<dyn Error>> {
    Ok(PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?)
}

#[tokio::test]
async fn migration_command_moves_fresh_database_to_head_idempotently() -> Result<(), Box<dyn Error>>
{
    let fixture = PostgresFixture::start().await?;
    let pool = pool(&fixture).await?;
    let source = CleanDirectory::new("migrations-fresh")?;
    write_migrations(
        source.path(),
        &[
            (
                "1_create_probe.sql",
                "CREATE TABLE migration_probe (id BIGINT PRIMARY KEY);",
            ),
            (
                "2_expand_probe.sql",
                "ALTER TABLE migration_probe ADD COLUMN expanded TEXT;",
            ),
        ],
    )?;
    let migrator = Migrator::new(source.path()).await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &migrator,
        SchemaVersionRange::new(1, 2)?,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;

    let MigrationCommandOutput::Status(fresh) = runner.execute(MigrationCommand::Status).await?
    else {
        return Err("status command returned migrate output".into());
    };
    assert_eq!(fresh.current_version, None);
    assert_eq!(fresh.pending_versions, vec![1, 2]);
    assert_eq!(
        runner.verify_compatibility().await,
        Err(MigrationError::SchemaUninitialized)
    );
    let mut connection = pool.acquire().await?;
    let history_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await?;
    assert!(!history_exists, "status must not mutate a fresh database");
    drop(connection);
    let startup_runner = MigrationRunner::new(
        pool.clone(),
        &migrator,
        SchemaVersionRange::new(1, 2)?,
        migration_config(true),
        DeploymentEnvironment::Test,
    )?;
    assert_eq!(
        startup_runner.apply_startup_policy().await?.current_version,
        Some(2)
    );

    let MigrationCommandOutput::Migrated(head) = runner.execute(MigrationCommand::Migrate).await?
    else {
        return Err("migrate command returned status output".into());
    };
    assert_eq!(head.current_version, Some(2));
    assert!(head.pending_versions.is_empty());
    assert_eq!(head.applied_count, 2);
    assert!(head.unknown_versions.is_empty());
    assert_eq!(runner.run().await?, head);

    let mut connection = pool.acquire().await?;
    let expanded_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'migration_probe' AND column_name = 'expanded')",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert!(expanded_exists);
    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn released_migration_checksum_is_immutable() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let mut settings = postgres_config(fixture.database_url().clone());
    settings.max_connections = 1;
    let pool = PostgresPool::connect(&settings, DeploymentEnvironment::Test).await?;
    let source = CleanDirectory::new("migrations-checksum")?;
    let path = source.path().join("1_create_checksum_probe.sql");
    fs::write(
        &path,
        "CREATE TABLE checksum_probe (id BIGINT PRIMARY KEY);",
    )?;
    let original = Migrator::new(source.path()).await?;
    let original_runner = MigrationRunner::new(
        pool.clone(),
        &original,
        SchemaVersionRange::new(1, 1)?,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;
    original_runner.run().await?;

    fs::write(
        &path,
        "CREATE TABLE checksum_probe (id BIGINT PRIMARY KEY, changed TEXT);",
    )?;
    let modified = Migrator::new(source.path()).await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &modified,
        SchemaVersionRange::new(1, 1)?,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;
    assert_eq!(runner.status().await?.checksum_mismatches, vec![1]);
    assert_eq!(runner.run().await, Err(MigrationError::ChecksumMismatch(1)));
    assert_eq!(original_runner.run().await?.current_version, Some(1));
    let mut connection = pool.acquire().await?;
    let held_advisory_locks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(held_advisory_locks, 0);
    drop(connection);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn timed_out_migration_discards_the_lock_holding_session() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let mut settings = postgres_config(fixture.database_url().clone());
    settings.max_connections = 1;
    let pool = PostgresPool::connect(&settings, DeploymentEnvironment::Test).await?;
    let source = CleanDirectory::new("migrations-timeout")?;
    write_migrations(
        source.path(),
        &[(
            "1_slow_probe.sql",
            "SELECT pg_sleep(1.5); CREATE TABLE slow_probe (id BIGINT PRIMARY KEY);",
        )],
    )?;
    let migrator = Migrator::new(source.path()).await?;
    let range = SchemaVersionRange::new(1, 1)?;
    let slow_runner = MigrationRunner::new(
        pool.clone(),
        &migrator,
        range,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(1),
        },
        DeploymentEnvironment::Test,
    )?;
    let started = Instant::now();
    assert_eq!(
        slow_runner.run().await,
        Err(MigrationError::OperationTimeout)
    );
    assert!(started.elapsed() < Duration::from_millis(1500));

    let retry_runner = MigrationRunner::new(
        pool.clone(),
        &migrator,
        range,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;
    assert_eq!(retry_runner.run().await?.current_version, Some(1));
    let mut connection = pool.acquire().await?;
    let held_advisory_locks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(held_advisory_locks, 0);
    drop(connection);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_migration_commands_share_the_database_lock() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = pool(&fixture).await?;
    let source = CleanDirectory::new("migrations-lock")?;
    write_migrations(
        source.path(),
        &[(
            "1_locked_probe.sql",
            "SELECT pg_sleep(0.25); CREATE TABLE locked_probe (id BIGINT PRIMARY KEY);",
        )],
    )?;
    let migrator = Migrator::new(source.path()).await?;
    let range = SchemaVersionRange::new(1, 1)?;
    let first = MigrationRunner::new(
        pool.clone(),
        &migrator,
        range,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;
    let second = MigrationRunner::new(
        pool.clone(),
        &migrator,
        range,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;

    let (first_result, second_result) = tokio::join!(first.run(), second.run());
    assert_eq!(first_result?.current_version, Some(1));
    assert_eq!(second_result?.current_version, Some(1));
    let mut connection = pool.acquire().await?;
    let history_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version = 1")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(history_rows, 1);
    drop(connection);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn expand_migration_keeps_declared_old_and_new_binaries_compatible()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = pool(&fixture).await?;
    let old_source = CleanDirectory::new("migrations-old")?;
    let new_source = CleanDirectory::new("migrations-new")?;
    let first = (
        "1_create_rolling_probe.sql",
        "CREATE TABLE rolling_probe (id BIGINT PRIMARY KEY);",
    );
    write_migrations(old_source.path(), &[first])?;
    write_migrations(
        new_source.path(),
        &[
            first,
            (
                "2_expand_rolling_probe.sql",
                "ALTER TABLE rolling_probe ADD COLUMN optional_value TEXT;",
            ),
        ],
    )?;
    let old_migrator = Migrator::new(old_source.path()).await?;
    let new_migrator = Migrator::new(new_source.path()).await?;
    let range = SchemaVersionRange::new(1, 2)?;
    let old_runner = MigrationRunner::new(
        pool.clone(),
        &old_migrator,
        range,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;
    old_runner.run().await?;
    let new_runner = MigrationRunner::new(
        pool.clone(),
        &new_migrator,
        range,
        migration_config(false),
        DeploymentEnvironment::Test,
    )?;

    assert_eq!(
        new_runner.verify_compatibility().await?.current_version,
        Some(1)
    );
    new_runner.run().await?;
    let old_status = old_runner.verify_compatibility().await?;
    assert_eq!(old_status.current_version, Some(2));
    assert_eq!(old_status.unknown_versions, vec![2]);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
