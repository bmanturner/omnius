//! Real PostgreSQL CRUD and database-constraint contracts.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_pagination::{CursorCodec, CursorSigningKey, PageLimit, PageRequest};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_reference_domain::{
    ReferenceRecord, ReferenceRecordId, ReferenceRecordPageRequest, ReferenceRecordPaginator,
    ReferenceRecordRepository, ReferenceRecordUpdate, ReferenceRecordVersion,
};
use rsk_reference_postgres::{
    PostgresReferenceRecordPaginator, PostgresReferenceRecordRepository, ReferenceStoreError,
};
use rsk_test_support::{PostgresFixture, TestClock, TestIds};
use sqlx::Connection as _;
use time::OffsetDateTime;
const SCHEMA_VERSION: i64 = 2_026_082_312;

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
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
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
    assert_eq!(record.version(), ReferenceRecordVersion::INITIAL);
    record.rename("Renamed record", renamed_at)?;
    let ReferenceRecordUpdate::Updated(updated) = repository.update(&record).await? else {
        panic!("current version did not update");
    };
    record = updated;
    assert_eq!(record.version().get(), 2);
    let missing = ReferenceRecord::create(missing_id, "Missing", clock.now())?;
    assert_eq!(
        repository.update(&missing).await?,
        ReferenceRecordUpdate::NotFound
    );

    assert!(repository.delete(id).await?);
    assert!(!repository.delete(id).await?);
    assert_eq!(repository.get(id).await?, None);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn repository_operations_honor_the_callers_transaction() -> Result<(), Box<dyn Error>> {
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
    let clock = TestClock::at(OffsetDateTime::from_unix_timestamp(1_787_443_200)?);
    let mut record = ReferenceRecord::create(id, "Transactional record", clock.now())?;
    let mut connection = pool.acquire().await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        repository.create_with(&mut transaction, &record).await?,
        record
    );
    transaction.rollback().await?;
    assert_eq!(repository.get(id).await?, None);

    let mut transaction = connection.begin().await?;
    repository.create_with(&mut transaction, &record).await?;
    record.rename(
        "Committed transaction",
        clock.advance(time::Duration::seconds(30))?,
    )?;
    let ReferenceRecordUpdate::Updated(updated) =
        repository.update_with(&mut transaction, &record).await?
    else {
        panic!("transactional update did not match current version");
    };
    record = updated;
    transaction.commit().await?;
    drop(connection);
    assert_eq!(repository.get(id).await?, Some(record));

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn version_check_prevents_concurrent_lost_updates() -> Result<(), Box<dyn Error>> {
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
    let id = ReferenceRecordId::from_uuid(TestIds::default().uuid_v7()?)?;
    let now = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
    let original = ReferenceRecord::create(id, "Original", now)?;
    repository.create(&original).await?;
    let mut left = original.clone();
    let mut right = original;
    left.rename("Left writer", now + time::Duration::seconds(1))?;
    right.rename("Right writer", now + time::Duration::seconds(1))?;

    let (left_outcome, right_outcome) =
        tokio::join!(repository.update(&left), repository.update(&right));
    let winner = match (left_outcome?, right_outcome?) {
        (ReferenceRecordUpdate::Updated(record), ReferenceRecordUpdate::VersionConflict)
        | (ReferenceRecordUpdate::VersionConflict, ReferenceRecordUpdate::Updated(record)) => {
            record
        }
        outcomes => panic!("expected one update and one version conflict, got {outcomes:?}"),
    };
    assert_eq!(winner.version().get(), 2);
    assert_eq!(repository.get(id).await?, Some(winner));

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn keyset_pages_are_bounded_stable_and_survive_row_changes() -> Result<(), Box<dyn Error>> {
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
    let codec = CursorCodec::new(CursorSigningKey::new([9; 32]));
    let paginator = PostgresReferenceRecordPaginator::new(pool.clone(), codec.clone());
    let ids = TestIds::default();
    let created_at = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
    let mut expected = Vec::with_capacity(137);
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    for index in 0..137 {
        let record = ReferenceRecord::create(
            ReferenceRecordId::from_uuid(ids.uuid_v7()?)?,
            format!("Record {index:03}"),
            created_at,
        )?;
        repository.create_with(&mut transaction, &record).await?;
        expected.push(record);
    }
    transaction.commit().await?;
    drop(connection);
    expected.sort_by_key(|record| (record.created_at(), record.id()));

    for requested_limit in [1, 7, 32, 100] {
        let limit = PageLimit::new(requested_limit)?;
        let mut transport = PageRequest::new(limit, None);
        let mut visited = Vec::new();
        loop {
            let request = ReferenceRecordPageRequest::decode(&transport, &codec)?;
            let page = paginator.list(request).await?;
            assert!(page.items.len() <= usize::from(requested_limit));
            visited.extend(page.items.into_iter().map(|record| record.id()));
            let Some(cursor) = page.next_cursor else {
                break;
            };
            transport = PageRequest::new(limit, Some(cursor));
        }
        assert_eq!(
            visited,
            expected.iter().map(ReferenceRecord::id).collect::<Vec<_>>()
        );
    }

    let limit = PageLimit::new(10)?;
    let first = paginator
        .list(ReferenceRecordPageRequest::first(limit))
        .await?;
    let continuation = first.next_cursor.ok_or("first page had no cursor")?;
    let first_ids = first
        .items
        .iter()
        .map(ReferenceRecord::id)
        .collect::<Vec<_>>();
    let cursor_id = *first_ids.last().ok_or("first page was empty")?;
    let deleted_unseen_id = expected[10].id();
    assert!(repository.delete(cursor_id).await?);
    assert!(repository.delete(deleted_unseen_id).await?);
    let inserted = ReferenceRecord::create(
        ReferenceRecordId::from_uuid(ids.uuid_v7()?)?,
        "Inserted between pages",
        created_at,
    )?;
    repository.create(&inserted).await?;

    let mut transport = PageRequest::new(limit, Some(continuation));
    let mut remaining_ids = Vec::new();
    loop {
        let request = ReferenceRecordPageRequest::decode(&transport, &codec)?;
        let page = paginator.list(request).await?;
        for record in &page.items {
            assert!(!first_ids.contains(&record.id()));
        }
        remaining_ids.extend(page.items.into_iter().map(|record| record.id()));
        let Some(cursor) = page.next_cursor else {
            break;
        };
        transport = PageRequest::new(limit, Some(cursor));
    }
    assert!(!remaining_ids.contains(&deleted_unseen_id));
    assert!(remaining_ids.contains(&inserted.id()));
    assert_eq!(first_ids.len() + remaining_ids.len(), 137);

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
