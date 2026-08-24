//! Real PostgreSQL CRUD and database-constraint contracts.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{PostgresConfig, PostgresPool, PostgresTlsMode};
use rsk_reference_domain::{ReferenceRecord, ReferenceRecordId, ReferenceRecordRepository};
use rsk_reference_postgres::{PostgresReferenceRecordRepository, ReferenceStoreError};
use rsk_test_support::{PostgresFixture, TestClock, TestIds};
use time::OffsetDateTime;

const SCHEMA_VERSION: i64 = 2_026_082_301;

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
        application_name: "rsk-reference-postgres-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
    }
}

#[tokio::test]
async fn checked_reference_record_crud_round_trips_domain_state() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(SCHEMA_VERSION, SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    let repository = PostgresReferenceRecordRepository::new(pool.clone());
    let ids = TestIds::default();
    let id = ReferenceRecordId::from_uuid(ids.uuid_v7()?)?;
    let missing_id = ReferenceRecordId::from_uuid(ids.uuid_v7()?)?;
    let clock = TestClock::at(OffsetDateTime::from_unix_timestamp(1_787_443_200)?);
    let mut record = ReferenceRecord::create(id, "First record", clock.now())?;

    assert_eq!(repository.create(&record).await?, record);
    assert_eq!(
        repository.create(&record).await,
        Err(ReferenceStoreError::Conflict)
    );
    assert_eq!(repository.get(id).await?, Some(record.clone()));
    assert_eq!(repository.get(missing_id).await?, None);

    let renamed_at = clock.advance(time::Duration::seconds(30))?;
    record.rename("Renamed record", renamed_at)?;
    assert_eq!(repository.update(&record).await?, Some(record.clone()));
    let missing = ReferenceRecord::create(missing_id, "Missing", clock.now())?;
    assert_eq!(repository.update(&missing).await?, None);

    assert!(repository.delete(id).await?);
    assert!(!repository.delete(id).await?);
    assert_eq!(repository.get(id).await?, None);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn database_rejects_invalid_reference_record_invariants() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(SCHEMA_VERSION, SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    let id = TestIds::default().uuid_v7()?;
    let now = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
    let mut connection = pool.acquire().await?;
    let result = sqlx::query!(
        r#"
        INSERT INTO reference_records (id, name, created_at, updated_at)
        VALUES ($1, $2, $3, $4)
        "#,
        id,
        "\t\n",
        now,
        now,
    )
    .execute(&mut *connection)
    .await;
    let Err(error) = result else {
        panic!("blank name did not violate the database check");
    };
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );
    let invalid_id_result = sqlx::query!(
        r#"
        INSERT INTO reference_records (id, name, created_at, updated_at)
        VALUES ($1, $2, $3, $4)
        "#,
        uuid::Uuid::nil(),
        "Valid name",
        now,
        now,
    )
    .execute(&mut *connection)
    .await;
    let Err(invalid_id_error) = invalid_id_result else {
        panic!("non-UUIDv7 identifier did not violate the database check");
    };
    assert_eq!(
        invalid_id_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );
    drop(connection);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
