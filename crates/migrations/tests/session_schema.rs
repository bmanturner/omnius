//! Browser-session provider and lifecycle-metadata schema contract.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use sqlx::postgres::PgQueryResult;
use time::OffsetDateTime;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const VALID_SESSION_ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const SHORT_SESSION_ID: &str = "AAAAAAAAAAAAAAAAAAAAA";
const INSERT_SESSION: &str = r"
    INSERT INTO sessions (
        session_id, user_id, device_id, created_at, last_seen_at,
        absolute_expires_at, revoked_at, user_agent_hash, ip_prefix
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet)
";

type IndexContract = (String, bool, Vec<String>, Option<String>);

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
        application_name: "rsk-session-schema-test".to_owned(),
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

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

fn assert_database_constraint(
    result: Result<PgQueryResult, sqlx::Error>,
    expected_code: &str,
    expected_constraint: &str,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = result else {
        return Err(format!("constraint {expected_constraint} accepted an invalid row").into());
    };
    let sqlx::Error::Database(database_error) = error else {
        return Err(format!("constraint {expected_constraint} returned {error}").into());
    };

    assert_eq!(database_error.code().as_deref(), Some(expected_code));
    assert_eq!(database_error.constraint(), Some(expected_constraint));
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps the exact provider, metadata, and cleanup contract visible"
)]
#[tokio::test]
async fn session_schema_enforces_provider_and_lifecycle_contract() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    let mut connection = pool.acquire().await?;

    let provider_tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || ':' || table_type FROM information_schema.tables \
         WHERE table_schema = 'tower_sessions' ORDER BY table_name",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(provider_tables, ["session:BASE TABLE"]);

    let provider_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = 'tower_sessions' \
           AND table_name = 'session' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        provider_columns,
        [
            "id:text:NO",
            "data:bytea:NO",
            "expiry_date:timestamp with time zone:NO",
        ]
    );

    let provider_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'tower_sessions.session'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(provider_constraints, ["session_pkey:p"]);
    let provider_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'tower_sessions' \
         AND tablename = 'session' ORDER BY indexname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        provider_indexes,
        ["session_expiry_date_idx", "session_pkey"]
    );

    let metadata_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
           AND table_name = 'sessions' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        metadata_columns,
        [
            "session_id:text:NO",
            "user_id:uuid:NO",
            "device_id:uuid:NO",
            "created_at:timestamp with time zone:NO",
            "last_seen_at:timestamp with time zone:NO",
            "absolute_expires_at:timestamp with time zone:NO",
            "revoked_at:timestamp with time zone:YES",
            "user_agent_hash:bytea:YES",
            "ip_prefix:inet:YES",
        ]
    );

    let metadata_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'sessions'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        metadata_constraints,
        [
            "sessions_absolute_expiry_valid:c",
            "sessions_device_id_uuid_v7:c",
            "sessions_pkey:p",
            "sessions_revocation_timeline:c",
            "sessions_session_id_length:c",
            "sessions_timeline:c",
            "sessions_user_agent_hash_length:c",
            "sessions_user_id_fkey:f",
        ]
    );

    let indexes: Vec<IndexContract> = sqlx::query_as(
        r"
        SELECT index_class.relname, idx.indisunique,
               ARRAY(
                   SELECT attribute.attname ||
                       CASE WHEN (idx.indoption[(key.ordinality - 1)::integer] & 1) = 1
                            THEN ' DESC' ELSE '' END
                   FROM unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinality)
                   JOIN pg_attribute AS attribute
                     ON attribute.attrelid = idx.indrelid
                    AND attribute.attnum = key.attnum
                   ORDER BY key.ordinality
               ),
               pg_get_expr(idx.indpred, idx.indrelid)
        FROM pg_index AS idx
        JOIN pg_class AS table_class ON table_class.oid = idx.indrelid
        JOIN pg_class AS index_class ON index_class.oid = idx.indexrelid
        WHERE table_class.oid = 'sessions'::regclass
          AND index_class.relname <> 'sessions_pkey'
        ORDER BY index_class.relname
        ",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        indexes,
        [
            (
                "sessions_active_device_idx".to_owned(),
                false,
                vec!["user_id".to_owned(), "device_id".to_owned()],
                Some("(revoked_at IS NULL)".to_owned()),
            ),
            (
                "sessions_active_expiry_idx".to_owned(),
                false,
                vec!["absolute_expires_at".to_owned()],
                Some("(revoked_at IS NULL)".to_owned()),
            ),
            (
                "sessions_active_user_idx".to_owned(),
                false,
                vec!["user_id".to_owned(), "created_at DESC".to_owned()],
                Some("(revoked_at IS NULL)".to_owned()),
            ),
            (
                "sessions_last_seen_cleanup_idx".to_owned(),
                false,
                vec!["last_seen_at".to_owned()],
                None,
            ),
            (
                "sessions_revoked_cleanup_idx".to_owned(),
                false,
                vec!["revoked_at".to_owned()],
                Some("(revoked_at IS NOT NULL)".to_owned()),
            ),
        ]
    );

    let user_id = Uuid::now_v7();
    let device_id = Uuid::now_v7();
    let now = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
    let expires_at = now + time::Duration::hours(8);
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(user_id)
        .bind(now)
        .execute(&mut *connection)
        .await?;

    sqlx::query(INSERT_SESSION)
        .bind(VALID_SESSION_ID)
        .bind(user_id)
        .bind(device_id)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Some([0x5a_u8; 32].as_slice()))
        .bind(Some("192.0.2.0/24"))
        .execute(&mut *connection)
        .await?;
    let stored_prefix: String =
        sqlx::query_scalar("SELECT ip_prefix::text FROM sessions WHERE session_id = $1")
            .bind(VALID_SESSION_ID)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(stored_prefix, "192.0.2.0/24");

    sqlx::query("INSERT INTO tower_sessions.session (id, data, expiry_date) VALUES ($1, $2, $3)")
        .bind(VALID_SESSION_ID)
        .bind([0x81_u8, 0xa1, 0x61, 0x01].as_slice())
        .bind(expires_at)
        .execute(&mut *connection)
        .await?;
    sqlx::query("DELETE FROM tower_sessions.session WHERE id = $1")
        .bind(VALID_SESSION_ID)
        .execute(&mut *connection)
        .await?;
    let metadata_survived_provider_cleanup: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_id = $1)")
            .bind(VALID_SESSION_ID)
            .fetch_one(&mut *connection)
            .await?;
    assert!(metadata_survived_provider_cleanup);

    let short_id = sqlx::query(INSERT_SESSION)
        .bind(SHORT_SESSION_ID)
        .bind(user_id)
        .bind(Uuid::now_v7())
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Option::<&[u8]>::None)
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(short_id, "23514", "sessions_session_id_length")?;

    let invalid_device = sqlx::query(INSERT_SESSION)
        .bind("BBBBBBBBBBBBBBBBBBBBBB")
        .bind(user_id)
        .bind(Uuid::nil())
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Option::<&[u8]>::None)
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_device, "23514", "sessions_device_id_uuid_v7")?;

    let invalid_hash = sqlx::query(INSERT_SESSION)
        .bind("CCCCCCCCCCCCCCCCCCCCCC")
        .bind(user_id)
        .bind(Uuid::now_v7())
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Some([0x5a_u8; 31].as_slice()))
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_hash, "23514", "sessions_user_agent_hash_length")?;

    let invalid_expiry = sqlx::query(INSERT_SESSION)
        .bind("DDDDDDDDDDDDDDDDDDDDDD")
        .bind(user_id)
        .bind(Uuid::now_v7())
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Option::<&[u8]>::None)
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_expiry, "23514", "sessions_absolute_expiry_valid")?;

    let invalid_last_seen = sqlx::query(INSERT_SESSION)
        .bind("EEEEEEEEEEEEEEEEEEEEEE")
        .bind(user_id)
        .bind(Uuid::now_v7())
        .bind(now)
        .bind(now - time::Duration::seconds(1))
        .bind(expires_at)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Option::<&[u8]>::None)
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_last_seen, "23514", "sessions_timeline")?;

    let invalid_revocation = sqlx::query(INSERT_SESSION)
        .bind("FFFFFFFFFFFFFFFFFFFFFF")
        .bind(user_id)
        .bind(Uuid::now_v7())
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(Some(now - time::Duration::seconds(1)))
        .bind(Option::<&[u8]>::None)
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_revocation, "23514", "sessions_revocation_timeline")?;

    let missing_user = sqlx::query(INSERT_SESSION)
        .bind("GGGGGGGGGGGGGGGGGGGGGG")
        .bind(Uuid::now_v7())
        .bind(Uuid::now_v7())
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(Option::<OffsetDateTime>::None)
        .bind(Option::<&[u8]>::None)
        .bind(Option::<&str>::None)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(missing_user, "23503", "sessions_user_id_fkey")?;

    let restricted_user_delete = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(restricted_user_delete, "23503", "sessions_user_id_fkey")?;

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
