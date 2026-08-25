//! Real PostgreSQL audit round-trip, transaction, append-only, and constraint contracts.

use std::{error::Error, time::Duration};

use rsk_audit::{
    AuditActor, AuditAppendOutcome, AuditConfig, AuditEvent, AuditEventType, AuditMetadata,
    AuditMetadataField, AuditOutcome, AuditReasonCode, AuditResourceId, AuditScope, AuditSinkError,
    PostgresAuditSink, SecurityEventName,
};
use rsk_auth_core::{SubjectId, TenantId};
use rsk_authz_basic::{Action, ResourceKind};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_core::{CausationId, CorrelationId, RequestId};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use serde_json::{Value, json};
use sqlx::{Connection as _, PgConnection, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_SCHEMA_HEAD: i64 = 2_026_082_313;

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 3,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-audit-test".to_owned(),
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

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(AUDIT_SCHEMA_HEAD, AUDIT_SCHEMA_HEAD)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase { pool, fixture })
}

async fn cleanup(database: TestDatabase) -> Result<(), Box<dyn Error>> {
    database.pool.close().await?;
    database.fixture.cleanup().await?;
    Ok(())
}

fn stable_time(seconds: i64) -> Result<OffsetDateTime, Box<dyn Error>> {
    Ok(OffsetDateTime::from_unix_timestamp(seconds)?)
}

fn basic_event(
    event_type: impl Into<AuditEventType>,
    occurred_at: OffsetDateTime,
    actor: AuditActor,
) -> Result<AuditEvent, Box<dyn Error>> {
    Ok(AuditEvent::builder(
        event_type,
        occurred_at,
        actor,
        AuditScope::Global,
        Action::new("identity.update")?,
        ResourceKind::new("identity")?,
        AuditOutcome::Succeeded,
    )
    .build())
}

fn database_code(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
}

async fn raw_insert(
    connection: &mut PgConnection,
    id: Uuid,
    actor_kind: &str,
    actor_subject_id: Option<Uuid>,
    subject_id: Option<Uuid>,
    metadata: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (
             id, occurred_at, event_type, actor_kind, actor_subject_id, subject_id,
             action, resource_kind, outcome, metadata
         ) VALUES ($1, $2, 'raw.constraint_test', $3, $4, $5,
                   'identity.update', 'identity', 'failed', $6)",
    )
    .bind(id)
    .bind(OffsetDateTime::now_utc())
    .bind(actor_kind)
    .bind(actor_subject_id)
    .bind(subject_id)
    .bind(sqlx::types::Json(metadata))
    .execute(connection)
    .await
    .map(|_| ())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves exact AC-AUTHZ-007 round-trip and commit/rollback coupling"
)]
#[tokio::test]
async fn append_round_trips_every_field_and_follows_the_caller_transaction()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let sink = PostgresAuditSink::default();
    let occurred_at = stable_time(1_800_000_000)?;
    let actor_subject_id = SubjectId::new();
    let affected_subject_id = SubjectId::new();
    let impersonator_subject_id = SubjectId::new();
    let tenant_id = TenantId::new();
    let request_id = RequestId::from_uuid(Uuid::nil());
    let correlation_id = CorrelationId::from_uuid(Uuid::from_u128(1));
    let causation_id = CausationId::from_uuid(Uuid::from_u128(2));
    let metadata = AuditMetadata::try_from_fields([
        AuditMetadataField::Attempt(3),
        AuditMetadataField::Cached(false),
        AuditMetadataField::Interactive(true),
    ])?;
    let event = AuditEvent::builder(
        SecurityEventName::AdministrativeIdentityAction,
        occurred_at,
        AuditActor::User(actor_subject_id),
        AuditScope::Tenant(tenant_id),
        Action::new("identity.update")?,
        ResourceKind::new("identity")?,
        AuditOutcome::Denied,
    )
    .subject_id(affected_subject_id)
    .impersonator_subject_id(impersonator_subject_id)?
    .resource_id(AuditResourceId::new("identity_123")?)
    .request_id(request_id)
    .correlation_id(correlation_id)
    .causation_id(causation_id)
    .reason(AuditReasonCode::new("authorization.policy_denied")?)
    .metadata(metadata)
    .build();

    let mut connection = database.pool.acquire().await?;
    sqlx::query("CREATE TABLE audit_test_effects (id integer PRIMARY KEY)")
        .execute(&mut *connection)
        .await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO audit_test_effects (id) VALUES (1)")
        .execute(&mut *transaction)
        .await?;
    assert_eq!(
        sink.append_with(&mut transaction, &event).await?,
        AuditAppendOutcome::Appended
    );
    transaction.commit().await?;

    let row = sqlx::query(
        "SELECT id, occurred_at, event_type, actor_kind, actor_subject_id, subject_id,
                impersonator_subject_id, effective_tenant_id, action, resource_kind, resource_id,
                outcome, request_id, correlation_id, causation_id, reason, metadata
         FROM audit_events WHERE id = $1",
    )
    .bind(event.id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.get::<Uuid, _>("id"), event.id().as_uuid());
    assert_eq!(row.get::<OffsetDateTime, _>("occurred_at"), occurred_at);
    assert_eq!(
        row.get::<String, _>("event_type"),
        "security.admin.identity_action"
    );
    assert_eq!(row.get::<String, _>("actor_kind"), "user");
    assert_eq!(
        row.get::<Option<Uuid>, _>("actor_subject_id"),
        Some(actor_subject_id.as_uuid())
    );
    assert_eq!(
        row.get::<Option<Uuid>, _>("subject_id"),
        Some(affected_subject_id.as_uuid())
    );
    assert_eq!(
        row.get::<Option<Uuid>, _>("impersonator_subject_id"),
        Some(impersonator_subject_id.as_uuid())
    );
    assert_eq!(
        row.get::<Option<Uuid>, _>("effective_tenant_id"),
        Some(tenant_id.as_uuid())
    );
    assert_eq!(row.get::<String, _>("action"), "identity.update");
    assert_eq!(row.get::<String, _>("resource_kind"), "identity");
    assert_eq!(
        row.get::<Option<String>, _>("resource_id").as_deref(),
        Some("identity_123")
    );
    assert_eq!(row.get::<String, _>("outcome"), "denied");
    assert_eq!(
        row.get::<Option<Uuid>, _>("request_id"),
        Some(request_id.as_uuid())
    );
    assert_eq!(
        row.get::<Option<Uuid>, _>("correlation_id"),
        Some(correlation_id.as_uuid())
    );
    assert_eq!(
        row.get::<Option<Uuid>, _>("causation_id"),
        Some(causation_id.as_uuid())
    );
    assert_eq!(
        row.get::<Option<String>, _>("reason").as_deref(),
        Some("authorization.policy_denied")
    );
    assert_eq!(
        row.get::<Value, _>("metadata"),
        json!({
            "attempt": 3,
            "cached": false,
            "interactive": true
        })
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_test_effects WHERE id = 1")
            .fetch_one(&mut *connection)
            .await?,
        1
    );

    let rolled_back = basic_event(
        AuditEventType::new("identity.rollback_test")?,
        stable_time(1_800_000_001)?,
        AuditActor::System,
    )?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO audit_test_effects (id) VALUES (2)")
        .execute(&mut *transaction)
        .await?;
    assert_eq!(
        sink.append_with(&mut transaction, &rolled_back).await?,
        AuditAppendOutcome::Appended
    );
    transaction.rollback().await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE id = $1 OR event_type = 'identity.rollback_test'",
        )
        .bind(rolled_back.id().as_uuid())
        .fetch_one(&mut *connection)
        .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_test_effects WHERE id = 2")
            .fetch_one(&mut *connection)
            .await?,
        0
    );

    let actor_cases = [
        ("actor.system", AuditActor::System, "system", None),
        ("actor.anonymous", AuditActor::Anonymous, "anonymous", None),
        (
            "actor.user",
            AuditActor::User(actor_subject_id),
            "user",
            Some(actor_subject_id.as_uuid()),
        ),
        (
            "actor.service_account",
            AuditActor::ServiceAccount(impersonator_subject_id),
            "service_account",
            Some(impersonator_subject_id.as_uuid()),
        ),
    ];
    let mut transaction = connection.begin().await?;
    for (name, actor, _, _) in actor_cases {
        let actor_event = basic_event(
            AuditEventType::new(name)?,
            stable_time(1_800_000_002)?,
            actor,
        )?;
        assert_eq!(
            sink.append_with(&mut transaction, &actor_event).await?,
            AuditAppendOutcome::Appended
        );
    }
    transaction.commit().await?;
    for (name, _, expected_kind, expected_subject) in actor_cases {
        let row = sqlx::query(
            "SELECT actor_kind, actor_subject_id FROM audit_events WHERE event_type = $1",
        )
        .bind(name)
        .fetch_one(&mut *connection)
        .await?;
        assert_eq!(row.get::<String, _>("actor_kind"), expected_kind);
        assert_eq!(
            row.get::<Option<Uuid>, _>("actor_subject_id"),
            expected_subject
        );
    }

    let disabled_event = basic_event(
        SecurityEventName::Login,
        stable_time(1_800_000_003)?,
        AuditActor::Anonymous,
    )?;
    let disabled = PostgresAuditSink::new(AuditConfig { enabled: false });
    assert_eq!(
        disabled
            .append_with(&mut connection, &disabled_event)
            .await?,
        AuditAppendOutcome::Disabled
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events WHERE id = $1")
            .bind(disabled_event.id().as_uuid())
            .fetch_one(&mut *connection)
            .await?,
        0
    );

    drop(connection);
    cleanup(database).await
}

#[tokio::test]
async fn database_rejects_mutation_and_revokes_public_mutation_privileges()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let sink = PostgresAuditSink::default();
    let event = basic_event(
        SecurityEventName::Login,
        stable_time(1_800_000_010)?,
        AuditActor::Anonymous,
    )?;
    let mut connection = database.pool.acquire().await?;
    assert_eq!(
        sink.append_with(&mut connection, &event).await?,
        AuditAppendOutcome::Appended
    );

    for statement in [
        "UPDATE audit_events SET outcome = 'failed'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ] {
        let error = sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .err()
            .ok_or("append-only mutation unexpectedly succeeded")?;
        assert_eq!(database_code(&error).as_deref(), Some("55000"));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM information_schema.role_table_grants
             WHERE table_schema = current_schema()
               AND table_name = 'audit_events'
               AND grantee = 'PUBLIC'
               AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')",
        )
        .fetch_one(&mut *connection)
        .await?,
        0
    );

    drop(connection);
    cleanup(database).await
}

#[tokio::test]
async fn sink_ignores_temporary_search_path_shadows() -> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let mut connection = database.pool.acquire().await?;
    sqlx::query("CREATE TEMP TABLE audit_events (LIKE public.audit_events INCLUDING ALL)")
        .execute(&mut *connection)
        .await?;
    let event = basic_event(
        AuditEventType::new("audit.search_path_shadow")?,
        stable_time(1_800_000_015)?,
        AuditActor::System,
    )?;

    assert_eq!(
        PostgresAuditSink::default()
            .append_with(&mut connection, &event)
            .await?,
        AuditAppendOutcome::Appended
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.audit_events WHERE id = $1")
            .bind(event.id().as_uuid())
            .fetch_one(&mut *connection)
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_temp.audit_events")
            .fetch_one(&mut *connection)
            .await?,
        0
    );

    drop(connection);
    cleanup(database).await
}

#[tokio::test]
async fn database_constraints_defend_identity_actor_and_metadata_invariants()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let mut connection = database.pool.acquire().await?;

    let invalid_id = raw_insert(
        &mut connection,
        Uuid::nil(),
        "system",
        None,
        None,
        json!({}),
    )
    .await
    .err()
    .ok_or("non-v7 audit identity unexpectedly succeeded")?;
    assert_eq!(database_code(&invalid_id).as_deref(), Some("23514"));

    let incoherent_actor = raw_insert(
        &mut connection,
        Uuid::now_v7(),
        "user",
        None,
        None,
        json!({}),
    )
    .await
    .err()
    .ok_or("incoherent actor unexpectedly succeeded")?;
    assert_eq!(database_code(&incoherent_actor).as_deref(), Some("23514"));

    let invalid_subject = raw_insert(
        &mut connection,
        Uuid::now_v7(),
        "system",
        None,
        Some(Uuid::nil()),
        json!({}),
    )
    .await
    .err()
    .ok_or("non-v7 subject unexpectedly succeeded")?;
    assert_eq!(database_code(&invalid_subject).as_deref(), Some("23514"));

    for unsafe_metadata in [
        json!({"nested": {"not": "scalar"}}),
        json!({"auth_token": 1}),
        json!({"note": "arbitrary text is prohibited"}),
        json!({"otp": 123_456}),
    ] {
        let error = raw_insert(
            &mut connection,
            Uuid::now_v7(),
            "anonymous",
            None,
            None,
            unsafe_metadata,
        )
        .await
        .err()
        .ok_or("unsafe raw metadata unexpectedly succeeded")?;
        assert_eq!(database_code(&error).as_deref(), Some("23514"));
    }

    let valid = basic_event(
        AuditEventType::new("duplicate.mapping")?,
        stable_time(1_800_000_020)?,
        AuditActor::System,
    )?;
    let sink = PostgresAuditSink::default();
    assert_eq!(
        sink.append_with(&mut connection, &valid).await?,
        AuditAppendOutcome::Appended
    );
    let error = sink.append_with(&mut connection, &valid).await;
    assert_eq!(error, Err(AuditSinkError::ConstraintViolation));
    let rendered = format!("{error:?}");
    assert!(!rendered.contains(valid.event_type().as_str()));
    assert!(!rendered.contains(&valid.id().to_string()));

    drop(connection);
    cleanup(database).await
}
