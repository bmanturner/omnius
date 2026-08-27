//! Append-only audit-event schema contract.

use std::{error::Error, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use sqlx::{PgConnection, Row, postgres::PgQueryResult};
use time::OffsetDateTime;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const AUDIT_HEAD: i64 = 2_026_082_312;
const OUTBOX_INBOX_HEAD: i64 = 2_026_082_313;
const CURRENT_HEAD: i64 = 2_026_082_314;
const AUDIT_ID_BASE: u128 = 0x018f_47a2_9b3c_7def_8abc_0000_0000_0000;
const SUBJECT_ID_BASE: u128 = 0x018f_47a2_9b3d_7def_8abc_0000_0000_0000;
const NON_V7_ID: Uuid = Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0000);

#[derive(Clone)]
struct AuditRow {
    id: Uuid,
    occurred_at: OffsetDateTime,
    event_type: String,
    actor_kind: String,
    actor_subject_id: Option<Uuid>,
    subject_id: Option<Uuid>,
    impersonator_subject_id: Option<Uuid>,
    effective_tenant_id: Option<Uuid>,
    action: String,
    resource_kind: String,
    resource_id: Option<String>,
    outcome: String,
    request_id: Option<Uuid>,
    correlation_id: Option<Uuid>,
    causation_id: Option<Uuid>,
    reason: Option<String>,
    metadata: String,
}

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
        application_name: "omnius-audit-schema-test".to_owned(),
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

async fn migrated_database() -> Result<(PostgresFixture, PostgresPool), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    Ok((fixture, pool))
}

fn audit_id(offset: u128) -> Uuid {
    Uuid::from_u128(AUDIT_ID_BASE + offset)
}

fn subject_id(offset: u128) -> Uuid {
    Uuid::from_u128(SUBJECT_ID_BASE + offset)
}

fn valid_row(offset: u128) -> Result<AuditRow, Box<dyn Error>> {
    Ok(AuditRow {
        id: audit_id(offset),
        occurred_at: OffsetDateTime::from_unix_timestamp(1_787_529_600)?,
        event_type: "authorization.decision".to_owned(),
        actor_kind: "user".to_owned(),
        actor_subject_id: Some(subject_id(1)),
        subject_id: Some(subject_id(2)),
        impersonator_subject_id: Some(subject_id(3)),
        effective_tenant_id: Some(subject_id(4)),
        action: "records:read".to_owned(),
        resource_kind: "reference_record".to_owned(),
        resource_id: Some("record-42".to_owned()),
        outcome: "succeeded".to_owned(),
        request_id: Some(Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_1001)),
        correlation_id: Some(Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_1002)),
        causation_id: Some(Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_1003)),
        reason: Some("policy.allowed".to_owned()),
        metadata: r#"{"attempt":2,"cached":false,"interactive":true}"#.to_owned(),
    })
}

async fn insert_event(
    connection: &mut PgConnection,
    row: &AuditRow,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO audit_events (
            id, occurred_at, event_type, actor_kind, actor_subject_id, subject_id,
            impersonator_subject_id, effective_tenant_id, action, resource_kind,
            resource_id, outcome, request_id, correlation_id, causation_id, reason, metadata
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17::jsonb
        )
        ",
    )
    .bind(row.id)
    .bind(row.occurred_at)
    .bind(&row.event_type)
    .bind(&row.actor_kind)
    .bind(row.actor_subject_id)
    .bind(row.subject_id)
    .bind(row.impersonator_subject_id)
    .bind(row.effective_tenant_id)
    .bind(&row.action)
    .bind(&row.resource_kind)
    .bind(&row.resource_id)
    .bind(&row.outcome)
    .bind(row.request_id)
    .bind(row.correlation_id)
    .bind(row.causation_id)
    .bind(&row.reason)
    .bind(&row.metadata)
    .execute(connection)
    .await
}

fn assert_database_constraint(
    result: Result<PgQueryResult, sqlx::Error>,
    expected_constraint: &str,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = result else {
        return Err(format!("constraint {expected_constraint} accepted an invalid row").into());
    };
    let sqlx::Error::Database(database_error) = error else {
        return Err(format!("constraint {expected_constraint} returned {error}").into());
    };

    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(database_error.constraint(), Some(expected_constraint));
    Ok(())
}

fn assert_mutation_rejected(
    result: Result<PgQueryResult, sqlx::Error>,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = result else {
        return Err("append-only audit table accepted mutation".into());
    };
    let sqlx::Error::Database(database_error) = error else {
        return Err(format!("audit mutation returned {error}").into());
    };

    assert_eq!(database_error.code().as_deref(), Some("55000"));
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps the exact audit catalog contract visible"
)]
#[tokio::test]
async fn audit_schema_catalog_matches_append_only_contract() -> Result<(), Box<dyn Error>> {
    let (fixture, pool) = migrated_database().await?;
    let mut connection = pool.acquire().await?;

    let applied_audit_versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations \
         WHERE success AND version = ANY($1) ORDER BY version DESC",
    )
    .bind(vec![CURRENT_HEAD, OUTBOX_INBOX_HEAD, AUDIT_HEAD])
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        applied_audit_versions,
        [CURRENT_HEAD, OUTBOX_INBOX_HEAD, AUDIT_HEAD]
    );

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
           AND table_name = 'audit_events' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        columns,
        [
            "id:uuid:NO",
            "occurred_at:timestamp with time zone:NO",
            "event_type:text:NO",
            "actor_kind:text:NO",
            "actor_subject_id:uuid:YES",
            "subject_id:uuid:YES",
            "impersonator_subject_id:uuid:YES",
            "effective_tenant_id:uuid:YES",
            "action:text:NO",
            "resource_kind:text:NO",
            "resource_id:text:YES",
            "outcome:text:NO",
            "request_id:uuid:YES",
            "correlation_id:uuid:YES",
            "causation_id:uuid:YES",
            "reason:text:YES",
            "metadata:jsonb:NO",
        ]
    );

    let constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'audit_events'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        constraints,
        [
            "audit_events_action_identifier:c",
            "audit_events_actor_kind_check:c",
            "audit_events_actor_subject_coherent:c",
            "audit_events_actor_subject_id_uuid_v7:c",
            "audit_events_effective_tenant_id_uuid_v7:c",
            "audit_events_event_type_identifier:c",
            "audit_events_id_uuid_v7:c",
            "audit_events_impersonator_coherent:c",
            "audit_events_impersonator_subject_id_uuid_v7:c",
            "audit_events_metadata_safe:c",
            "audit_events_outcome_check:c",
            "audit_events_pkey:p",
            "audit_events_reason_identifier:c",
            "audit_events_resource_id_identifier:c",
            "audit_events_resource_kind_identifier:c",
            "audit_events_subject_id_uuid_v7:c",
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
        WHERE table_class.oid = 'audit_events'::regclass
          AND index_class.relname <> 'audit_events_pkey'
        ORDER BY index_class.relname
        ",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        indexes,
        [
            (
                "audit_events_actor_time_idx".to_owned(),
                false,
                vec![
                    "actor_subject_id".to_owned(),
                    "occurred_at DESC".to_owned(),
                    "id DESC".to_owned(),
                ],
                None,
            ),
            (
                "audit_events_correlation_time_idx".to_owned(),
                false,
                vec![
                    "correlation_id".to_owned(),
                    "occurred_at DESC".to_owned(),
                    "id DESC".to_owned(),
                ],
                None,
            ),
            (
                "audit_events_tenant_time_idx".to_owned(),
                false,
                vec![
                    "effective_tenant_id".to_owned(),
                    "occurred_at DESC".to_owned(),
                    "id DESC".to_owned(),
                ],
                None,
            ),
        ]
    );

    let validator_contract: (String, bool, String) = sqlx::query_as(
        "SELECT provolatile::text, proisstrict, proparallel::text \
         FROM pg_proc WHERE oid = 'audit_metadata_is_safe(jsonb)'::regprocedure",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(validator_contract, ("i".to_owned(), true, "s".to_owned()));

    let triggers: Vec<(String, i16, String)> = sqlx::query_as(
        "SELECT trigger.tgname, trigger.tgtype, procedure.proname \
         FROM pg_trigger AS trigger \
         JOIN pg_proc AS procedure ON procedure.oid = trigger.tgfoid \
         WHERE trigger.tgrelid = 'audit_events'::regclass \
           AND NOT trigger.tgisinternal ORDER BY trigger.tgname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        triggers,
        [(
            "audit_events_reject_mutation".to_owned(),
            58,
            "reject_audit_event_mutation".to_owned()
        )]
    );

    let public_mutation_grants: Vec<String> = sqlx::query_scalar(
        "SELECT privilege_type FROM information_schema.role_table_grants \
         WHERE table_schema = current_schema() AND table_name = 'audit_events' \
           AND grantee = 'PUBLIC' AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert!(public_mutation_grants.is_empty());

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one isolated database covers mutually dependent row-shape constraints"
)]
#[tokio::test]
async fn audit_schema_enforces_identifiers_actors_uuid_versions_and_roundtrip()
-> Result<(), Box<dyn Error>> {
    let (fixture, pool) = migrated_database().await?;
    let mut connection = pool.acquire().await?;

    let exact = valid_row(1)?;
    insert_event(&mut connection, &exact).await?;
    let stored = sqlx::query("SELECT * FROM audit_events WHERE id = $1")
        .bind(exact.id)
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(stored.try_get::<Uuid, _>("id")?, exact.id);
    assert_eq!(
        stored.try_get::<OffsetDateTime, _>("occurred_at")?,
        exact.occurred_at
    );
    assert_eq!(stored.try_get::<String, _>("event_type")?, exact.event_type);
    assert_eq!(stored.try_get::<String, _>("actor_kind")?, exact.actor_kind);
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("actor_subject_id")?,
        exact.actor_subject_id
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("subject_id")?,
        exact.subject_id
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("impersonator_subject_id")?,
        exact.impersonator_subject_id
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("effective_tenant_id")?,
        exact.effective_tenant_id
    );
    assert_eq!(stored.try_get::<String, _>("action")?, exact.action);
    assert_eq!(
        stored.try_get::<String, _>("resource_kind")?,
        exact.resource_kind
    );
    assert_eq!(
        stored.try_get::<Option<String>, _>("resource_id")?,
        exact.resource_id
    );
    assert_eq!(stored.try_get::<String, _>("outcome")?, exact.outcome);
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("request_id")?,
        exact.request_id
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("correlation_id")?,
        exact.correlation_id
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("causation_id")?,
        exact.causation_id
    );
    assert_eq!(stored.try_get::<Option<String>, _>("reason")?, exact.reason);
    let metadata_text: String =
        sqlx::query_scalar("SELECT metadata::text FROM audit_events WHERE id = $1")
            .bind(exact.id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(
        metadata_text,
        r#"{"cached": false, "attempt": 2, "interactive": true}"#
    );

    for (offset, actor_kind, actor_subject_id) in [
        (2, "user", Some(subject_id(10))),
        (3, "service_account", Some(subject_id(11))),
        (4, "anonymous", None),
        (5, "system", None),
    ] {
        let mut row = valid_row(offset)?;
        row.actor_kind = actor_kind.to_owned();
        row.actor_subject_id = actor_subject_id;
        row.impersonator_subject_id = (actor_kind == "user").then(|| subject_id(3));
        insert_event(&mut connection, &row).await?;
    }

    for (offset, outcome) in [(6, "succeeded"), (7, "denied"), (8, "failed")] {
        let mut row = valid_row(offset)?;
        row.outcome = outcome.to_owned();
        insert_event(&mut connection, &row).await?;
    }

    let mut incoherent_actor = valid_row(20)?;
    incoherent_actor.actor_subject_id = None;
    assert_database_constraint(
        insert_event(&mut connection, &incoherent_actor).await,
        "audit_events_actor_subject_coherent",
    )?;
    incoherent_actor.actor_kind = "system".to_owned();
    incoherent_actor.actor_subject_id = Some(subject_id(12));
    assert_database_constraint(
        insert_event(&mut connection, &incoherent_actor).await,
        "audit_events_actor_subject_coherent",
    )?;
    let mut incoherent_impersonator = valid_row(21)?;
    incoherent_impersonator.impersonator_subject_id = incoherent_impersonator.actor_subject_id;
    assert_database_constraint(
        insert_event(&mut connection, &incoherent_impersonator).await,
        "audit_events_impersonator_coherent",
    )?;
    incoherent_impersonator.actor_kind = "system".to_owned();
    incoherent_impersonator.actor_subject_id = None;
    incoherent_impersonator.impersonator_subject_id = Some(subject_id(13));
    assert_database_constraint(
        insert_event(&mut connection, &incoherent_impersonator).await,
        "audit_events_impersonator_coherent",
    )?;
    let mut unknown_actor = valid_row(20)?;
    unknown_actor.actor_kind = "operator".to_owned();
    assert_database_constraint(
        insert_event(&mut connection, &unknown_actor).await,
        "audit_events_actor_kind_check",
    )?;
    let mut unknown_outcome = valid_row(20)?;
    unknown_outcome.outcome = "allowed".to_owned();
    assert_database_constraint(
        insert_event(&mut connection, &unknown_outcome).await,
        "audit_events_outcome_check",
    )?;

    for (field, expected_constraint) in [
        ("id", "audit_events_id_uuid_v7"),
        ("actor", "audit_events_actor_subject_id_uuid_v7"),
        ("subject", "audit_events_subject_id_uuid_v7"),
        (
            "impersonator",
            "audit_events_impersonator_subject_id_uuid_v7",
        ),
        ("tenant", "audit_events_effective_tenant_id_uuid_v7"),
    ] {
        let mut row = valid_row(21)?;
        match field {
            "id" => row.id = NON_V7_ID,
            "actor" => row.actor_subject_id = Some(NON_V7_ID),
            "subject" => row.subject_id = Some(NON_V7_ID),
            "impersonator" => row.impersonator_subject_id = Some(NON_V7_ID),
            "tenant" => row.effective_tenant_id = Some(NON_V7_ID),
            _ => unreachable!(),
        }
        assert_database_constraint(
            insert_event(&mut connection, &row).await,
            expected_constraint,
        )?;
    }

    let portable_limit = "a".repeat(128);
    let mut boundary = valid_row(30)?;
    boundary.event_type.clone_from(&portable_limit);
    boundary.action.clone_from(&portable_limit);
    boundary.resource_kind.clone_from(&portable_limit);
    boundary.resource_id = Some(portable_limit.clone());
    boundary.reason = Some(portable_limit);
    insert_event(&mut connection, &boundary).await?;

    for (field, expected_constraint) in [
        ("event", "audit_events_event_type_identifier"),
        ("action", "audit_events_action_identifier"),
        ("kind", "audit_events_resource_kind_identifier"),
        ("resource", "audit_events_resource_id_identifier"),
        ("reason", "audit_events_reason_identifier"),
    ] {
        let mut row = valid_row(31)?;
        let invalid = if field == "event" {
            "bad/value".to_owned()
        } else {
            "a".repeat(129)
        };
        match field {
            "event" => row.event_type = invalid,
            "action" => row.action = invalid,
            "kind" => row.resource_kind = invalid,
            "resource" => row.resource_id = Some(invalid),
            "reason" => row.reason = Some(invalid),
            _ => unreachable!(),
        }
        assert_database_constraint(
            insert_event(&mut connection, &row).await,
            expected_constraint,
        )?;
    }

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn audit_schema_rejects_unsafe_metadata() -> Result<(), Box<dyn Error>> {
    let (fixture, pool) = migrated_database().await?;
    let mut connection = pool.acquire().await?;

    for (offset, metadata) in [
        (1, "[]"),
        (2, r#"{"nested":{"value":1}}"#),
        (3, r#"{"note":"actual-secret"}"#),
        (4, r#"{"otp":123456}"#),
        (5, r#"{"attempt":256}"#),
        (6, r#"{"attempt":-1}"#),
        (7, r#"{"attempt":1.5}"#),
        (8, r#"{"attempt":"3"}"#),
        (9, r#"{"cached":1}"#),
        (10, r#"{"interactive":null}"#),
        (11, r#"{"privateKey":1}"#),
        (12, r#"{"before":1}"#),
    ] {
        let mut row = valid_row(100 + offset)?;
        row.metadata = metadata.to_owned();
        assert_database_constraint(
            insert_event(&mut connection, &row).await,
            "audit_events_metadata_safe",
        )?;
    }

    let mut safe_boundary = valid_row(140)?;
    safe_boundary.metadata = r#"{"attempt":255,"cached":true,"interactive":false}"#.to_owned();
    insert_event(&mut connection, &safe_boundary).await?;

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn audit_schema_rejects_every_mutation_and_retains_original_row() -> Result<(), Box<dyn Error>>
{
    let (fixture, pool) = migrated_database().await?;
    let mut connection = pool.acquire().await?;
    let original = valid_row(200)?;
    insert_event(&mut connection, &original).await?;

    assert_mutation_rejected(
        sqlx::query("UPDATE audit_events SET outcome = 'failed' WHERE id = $1")
            .bind(original.id)
            .execute(&mut *connection)
            .await,
    )?;
    assert_mutation_rejected(
        sqlx::query("DELETE FROM audit_events WHERE id = $1")
            .bind(original.id)
            .execute(&mut *connection)
            .await,
    )?;
    assert_mutation_rejected(
        sqlx::query("TRUNCATE audit_events")
            .execute(&mut *connection)
            .await,
    )?;

    let retained: (i64, String) =
        sqlx::query_as("SELECT count(*), min(outcome) FROM audit_events WHERE id = $1")
            .bind(original.id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(retained, (1, "succeeded".to_owned()));

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
