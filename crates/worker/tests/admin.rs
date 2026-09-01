//! Real PostgreSQL proof for protected, AAL2, durable-audit worker diagnostics.

use std::{error::Error, sync::Arc, time::Duration};

use omnius_admin::{
    AdminAuthorityResolver, AdminConfig, AdminLineage, AdminPermission,
    AuthorityResolvedImpersonationTarget, ImpersonationTarget, admin_policy_rules,
};
use omnius_audit::{AuditConfig, AuditReasonCode, PostgresAuditSink};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId};
use omnius_authz_basic::{AuthorizationContext, BasicPolicy, PolicyMatrix};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_core::{
    BuildMetadata, BuildMetadataInput, Clock, CorrelationId, RequestId, SchemaCompatibility,
};
use omnius_health::{HealthBuilder, HealthConfig};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use omnius_worker::{BackendId, ProtectedWorkerAdmin, WorkerAdminError, WorkerBuilder};
use sqlx::Row as _;
use time::OffsetDateTime;
use uuid::Uuid;

const SCHEMA_HEAD: i64 = 2_026_082_314;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

struct TestClock(OffsetDateTime);

impl Clock for TestClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

struct FixedAuthority {
    denied_subject: SubjectId,
    authorized: AuthorizationContext,
    denied: AuthorizationContext,
}

impl AdminAuthorityResolver for FixedAuthority {
    fn resolve(&self, principal: &Principal) -> Option<AuthorizationContext> {
        if principal.subject_id == self.denied_subject {
            Some(self.denied.clone())
        } else {
            Some(self.authorized.clone())
        }
    }

    fn resolve_target(
        &self,
        _target: ImpersonationTarget,
    ) -> Option<AuthorityResolvedImpersonationTarget> {
        None
    }
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
        max_lifetime: Duration::from_mins(1),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-worker-test".to_owned(),
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
        SchemaVersionRange::new(SCHEMA_HEAD, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

fn metadata() -> Result<BuildMetadata, Box<dyn Error>> {
    Ok(BuildMetadata::current(BuildMetadataInput {
        service: "worker-test",
        profile: "worker",
        modules: &["runtime", "health", "admin", "audit"],
        providers: &[],
        schema: SchemaCompatibility {
            minimum: "2026082314",
            maximum: "2026082314",
        },
    })?)
}

fn principal(now: OffsetDateTime, assurance: AssuranceLevel) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::new(),
        PrincipalKind::User,
        None,
        AuthMethod::WebAuthn,
        now,
        assurance,
        Vec::<Scope>::new(),
    )?)
}

fn lineage() -> AdminLineage {
    AdminLineage {
        request_id: RequestId::from_uuid(Uuid::now_v7()),
        correlation_id: CorrelationId::from_uuid(Uuid::now_v7()),
        causation_id: None,
    }
}

async fn wait_for_audit_event(
    pool: &PostgresPool,
    request_id: RequestId,
    action: &str,
    event_type: &str,
) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*)::bigint FROM audit_events \
                 WHERE request_id = $1 AND action = $2 AND event_type = $3",
            )
            .bind(request_id.as_uuid())
            .bind(action)
            .bind(event_type)
            .fetch_one(&pool.sqlx_pool())
            .await?;
            if count == 1 {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

async fn assert_status_auth_outcomes_and_audit(
    service: &ProtectedWorkerAdmin<BasicPolicy, FixedAuthority>,
    database: &TestDatabase,
    allowed: &Principal,
    low_assurance: &Principal,
    denied: &Principal,
) -> Result<(), Box<dyn Error>> {
    let reason = AuditReasonCode::new("worker_incident")?;
    let request_lineage = lineage();

    assert_eq!(
        service
            .status(low_assurance, reason.clone(), request_lineage)
            .await,
        Err(WorkerAdminError::InsufficientAssurance)
    );
    assert_eq!(
        service
            .status(denied, reason.clone(), request_lineage)
            .await,
        Err(WorkerAdminError::AuthorizationDenied)
    );
    let status = service.status(allowed, reason, request_lineage).await?;
    assert!(!status.draining);

    let rows = sqlx::query(
        "SELECT event_type, outcome, request_id, correlation_id, reason, metadata::text AS metadata \
         FROM audit_events WHERE action = 'admin:worker:status' ORDER BY occurred_at, event_type",
    )
    .fetch_all(&database.pool.sqlx_pool())
    .await?;
    assert_eq!(rows.len(), 4);
    let denied_count = rows
        .iter()
        .filter(|row| row.get::<String, _>("outcome") == "denied")
        .count();
    let succeeded_count = rows
        .iter()
        .filter(|row| row.get::<String, _>("outcome") == "succeeded")
        .count();
    assert_eq!((denied_count, succeeded_count), (2, 2));
    assert!(rows.iter().all(|row| {
        let event_type = row.get::<String, _>("event_type");
        row.get::<Uuid, _>("request_id") == request_lineage.request_id.as_uuid()
            && row.get::<Uuid, _>("correlation_id") == request_lineage.correlation_id.as_uuid()
            && matches!(
                event_type.as_str(),
                "security.admin.worker.authorized" | "security.admin.worker.completed"
            )
            && !row.get::<String, _>("reason").is_empty()
            && !row.get::<String, _>("metadata").contains("payload")
    }));
    Ok(())
}

async fn assert_cancelled<T>(task: tokio::task::JoinHandle<T>, operation: &str) {
    let Err(error) = task.await else {
        panic!("{operation} caller must be cancelled");
    };
    assert!(error.is_cancelled());
}

async fn assert_status_cancellation_continues_audit(
    service: &Arc<ProtectedWorkerAdmin<BasicPolicy, FixedAuthority>>,
    database: &TestDatabase,
    allowed: &Principal,
) -> Result<(), Box<dyn Error>> {
    let mut gate = database.pool.sqlx_pool().acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(76076)")
        .execute(&mut *gate)
        .await?;
    let request_lineage = lineage();
    let reason = AuditReasonCode::new("cancelled_worker_status")?;
    let task = {
        let service = Arc::clone(service);
        let allowed = allowed.clone();
        tokio::spawn(async move { service.status(&allowed, reason, request_lineage).await })
    };
    wait_for_audit_event(
        &database.pool,
        request_lineage.request_id,
        "admin:worker:status",
        "security.admin.worker.authorized",
    )
    .await?;
    task.abort();
    assert_cancelled(task, "status").await;

    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(76076)")
        .fetch_one(&mut *gate)
        .await?;
    assert!(unlocked);
    wait_for_audit_event(
        &database.pool,
        request_lineage.request_id,
        "admin:worker:status",
        "security.admin.worker.completed",
    )
    .await
}

async fn assert_dead_list_cancellation_continues_audit(
    service: &Arc<ProtectedWorkerAdmin<BasicPolicy, FixedAuthority>>,
    database: &TestDatabase,
    allowed: &Principal,
) -> Result<(), Box<dyn Error>> {
    let mut gate = database.pool.sqlx_pool().acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(76076)")
        .execute(&mut *gate)
        .await?;
    let request_lineage = lineage();
    let missing_backend = BackendId::new("redis:missing")?;
    let reason = AuditReasonCode::new("cancelled_worker_dead_list")?;
    let task = {
        let service = Arc::clone(service);
        let allowed = allowed.clone();
        tokio::spawn(async move {
            service
                .dead_records(&allowed, &missing_backend, 1, reason, request_lineage)
                .await
        })
    };
    wait_for_audit_event(
        &database.pool,
        request_lineage.request_id,
        "admin:worker:dead:list",
        "security.admin.worker.authorized",
    )
    .await?;
    task.abort();
    assert_cancelled(task, "dead-list").await;

    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(76076)")
        .fetch_one(&mut *gate)
        .await?;
    assert!(unlocked);
    wait_for_audit_event(
        &database.pool,
        request_lineage.request_id,
        "admin:worker:dead:list",
        "security.admin.worker.completed",
    )
    .await
}

#[tokio::test]
async fn status_requires_capability_and_aal2_and_durably_audits_every_outcome()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let allowed = principal(now, AssuranceLevel::Aal2)?;
    let low_assurance = principal(now, AssuranceLevel::Aal1)?;
    let denied = principal(now, AssuranceLevel::Aal2)?;
    let authorized_context = AuthorizationContext::new(
        vec![],
        vec![],
        vec![
            AdminPermission::WorkerStatus.capability()?,
            AdminPermission::WorkerDeadList.capability()?,
        ],
        vec![],
    )?;
    let denied_context = AuthorizationContext::default();
    let authority = FixedAuthority {
        denied_subject: denied.subject_id,
        authorized: authorized_context,
        denied: denied_context,
    };
    let health = HealthBuilder::new(metadata()?, HealthConfig::default())?.build();
    let runtime = WorkerBuilder::new(health)?.start()?;
    let diagnostics = runtime.diagnostics().clone();
    let service = Arc::new(ProtectedWorkerAdmin::new(
        BasicPolicy::new(PolicyMatrix::new(admin_policy_rules()?)?),
        authority,
        diagnostics,
        Arc::new(TestClock(now)),
        PostgresAuditSink::new(AuditConfig { enabled: true }),
        database.pool.clone(),
        AdminConfig::default(),
    )?);
    assert_status_auth_outcomes_and_audit(&service, &database, &allowed, &low_assurance, &denied)
        .await?;

    sqlx::query(
        "CREATE FUNCTION public.omnius_worker_completion_gate() \
         RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
             IF NEW.event_type = 'security.admin.worker.completed' THEN \
                 PERFORM pg_advisory_xact_lock(76076); \
             END IF; \
             RETURN NEW; \
         END $$",
    )
    .execute(&database.pool.sqlx_pool())
    .await?;
    sqlx::query(
        "CREATE TRIGGER omnius_worker_completion_gate \
         BEFORE INSERT ON audit_events FOR EACH ROW \
         EXECUTE FUNCTION public.omnius_worker_completion_gate()",
    )
    .execute(&database.pool.sqlx_pool())
    .await?;

    assert_status_cancellation_continues_audit(&service, &database, &allowed).await?;
    assert_dead_list_cancellation_continues_audit(&service, &database, &allowed).await?;

    let report = runtime.shutdown().await;
    assert!(report.forced.is_empty());
    Ok(())
}
