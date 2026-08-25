//! Real PostgreSQL proof for audited, fail-closed impersonation starts.

use std::{error::Error, sync::Arc, time::Duration};

use rsk_admin::{
    AdminAuthorityResolver, AdminConfig, AdminError, AdminExecutionError, AdminLineage,
    AdminOperationHandler, AdminPermission, AdminService, AuthorityResolvedImpersonationTarget,
    AuthorizedImpersonation, ImpersonationTarget, admin_policy_rules,
};
use rsk_audit::{AuditConfig, AuditReasonCode, PostgresAuditSink};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId};
use rsk_authz_basic::{AuthorizationContext, BasicPolicy, DenyReason, PolicyMatrix};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_core::{Clock, CorrelationId, RequestId};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use sqlx::{PgConnection, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_SCHEMA_HEAD: i64 = 2_026_082_313;

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
}

struct TestClock(OffsetDateTime);

impl Clock for TestClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Clone)]
struct FixedAuthority {
    context: AuthorizationContext,
    target: Principal,
}

impl AdminAuthorityResolver for FixedAuthority {
    fn resolve(&self, _principal: &Principal) -> Option<AuthorizationContext> {
        Some(self.context.clone())
    }

    fn resolve_target(
        &self,
        target: ImpersonationTarget,
    ) -> Option<AuthorityResolvedImpersonationTarget> {
        (target.subject_id() == self.target.subject_id && target.tenant_id().is_none())
            .then(|| AuthorityResolvedImpersonationTarget::Global(self.target.clone()))
    }
}

struct SqlProbeOperations;

impl SqlProbeOperations {
    async fn probe(
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<SubjectId, sqlx::Error> {
        let subject_id = authority.subject_id();
        sqlx::query_scalar::<_, Uuid>("SELECT $1::uuid")
            .bind(subject_id.as_uuid())
            .fetch_one(connection)
            .await?;
        Ok(subject_id)
    }
}

impl AdminOperationHandler for SqlProbeOperations {
    type Output = SubjectId;
    type RepairRequest = ();
    type FeatureOverrideRequest = ();
    type Error = sqlx::Error;

    async fn lookup_user(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        Self::probe(connection, authority).await
    }

    async fn lookup_tenant(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        Self::probe(connection, authority).await
    }

    async fn suspend_user(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        Self::probe(connection, authority).await
    }

    async fn suspend_tenant(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        Self::probe(connection, authority).await
    }

    async fn execute_safe_repair(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
        (): Self::RepairRequest,
    ) -> Result<Self::Output, Self::Error> {
        Self::probe(connection, authority).await
    }

    async fn apply_feature_override(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
        (): Self::FeatureOverrideRequest,
    ) -> Result<Self::Output, Self::Error> {
        Self::probe(connection, authority).await
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
        application_name: "rsk-admin-test".to_owned(),
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

fn principal(now: OffsetDateTime) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::new(),
        PrincipalKind::User,
        None,
        AuthMethod::WebAuthn,
        now,
        AssuranceLevel::Aal2,
        Vec::<Scope>::new(),
    )?)
}

fn service(
    now: OffsetDateTime,
    audit: PostgresAuditSink,
    authority: AuthorizationContext,
    target: Principal,
) -> Result<AdminService<BasicPolicy, FixedAuthority, SqlProbeOperations>, Box<dyn Error>> {
    Ok(AdminService::new(
        BasicPolicy::new(PolicyMatrix::new(admin_policy_rules()?)?),
        FixedAuthority {
            context: authority,
            target,
        },
        SqlProbeOperations,
        Arc::new(TestClock(now)),
        audit,
        AdminConfig::default(),
    )?)
}

fn lineage() -> AdminLineage {
    AdminLineage {
        request_id: RequestId::from_uuid(Uuid::from_u128(1)),
        correlation_id: CorrelationId::from_uuid(Uuid::from_u128(2)),
        causation_id: None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one isolated database proves committed success, denial, and disabled-audit contracts"
)]
#[tokio::test]
async fn impersonation_start_is_permissioned_audited_and_commit_bound() -> Result<(), Box<dyn Error>>
{
    let database = test_database().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let administrator = principal(now)?;
    let target_principal = principal(now)?;
    let target = ImpersonationTarget::global(target_principal.subject_id);
    let authorized = AuthorizationContext::new(
        vec![],
        vec![],
        vec![
            AdminPermission::StartImpersonation.capability()?,
            AdminPermission::UserLookup.capability()?,
            AdminPermission::EndImpersonation.capability()?,
        ],
        vec![],
    )?;
    let admin_service = service(
        now,
        PostgresAuditSink::default(),
        authorized.clone(),
        target_principal.clone(),
    )?;
    let context = admin_service
        .start_impersonation(
            &database.pool,
            &administrator,
            target,
            AuditReasonCode::new("support.case_42")?,
            Duration::from_mins(15),
            lineage(),
        )
        .await?;
    assert_eq!(context.status_label(), "IMPERSONATION ACTIVE");
    let display = context.display();
    assert_eq!(display.effective_subject_id, target_principal.subject_id);
    assert_eq!(display.impersonator_subject_id, administrator.subject_id);
    assert_eq!(display.effective_tenant_id, None);
    let intruder = principal(now)?;
    let mismatched = admin_service
        .lookup_user(
            &database.pool,
            &intruder,
            &context,
            AuditReasonCode::new("support.case_42")?,
            lineage(),
        )
        .await;
    assert!(matches!(
        mismatched,
        Err(AdminExecutionError::Admin(AdminError::ContextMismatch))
    ));
    let looked_up_subject = admin_service
        .lookup_user(
            &database.pool,
            &administrator,
            &context,
            AuditReasonCode::new("support.case_42")?,
            lineage(),
        )
        .await?;
    assert_eq!(looked_up_subject, target_principal.subject_id);
    admin_service
        .end_impersonation(
            &database.pool,
            &administrator,
            context,
            AuditReasonCode::new("support.case_42")?,
            lineage(),
        )
        .await?;
    let retry_context = admin_service
        .start_impersonation(
            &database.pool,
            &administrator,
            target,
            AuditReasonCode::new("support.case_46")?,
            Duration::from_mins(15),
            lineage(),
        )
        .await?;
    let retryable_end = match service(
        now,
        PostgresAuditSink::new(AuditConfig { enabled: false }),
        authorized.clone(),
        target_principal.clone(),
    )?
    .end_impersonation(
        &database.pool,
        &administrator,
        retry_context,
        AuditReasonCode::new("support.case_46")?,
        lineage(),
    )
    .await
    {
        Ok(()) => return Err("disabled audit unexpectedly ended impersonation".into()),
        Err(error) => error,
    };
    assert_eq!(retryable_end.error(), AdminError::AuditDisabled);
    let Some(returned_context) = retryable_end.into_context() else {
        return Err("pre-commit failure consumed impersonation context".into());
    };
    assert_eq!(returned_context.status_label(), "IMPERSONATION ACTIVE");
    admin_service
        .end_impersonation(
            &database.pool,
            &administrator,
            returned_context,
            AuditReasonCode::new("support.case_46")?,
            lineage(),
        )
        .await?;
    let mut connection = database.pool.acquire().await?;
    let succeeded = sqlx::query(
        "SELECT actor_kind, actor_subject_id, subject_id, impersonator_subject_id,
                effective_tenant_id, action, resource_kind, outcome, request_id,
                correlation_id, reason, metadata
         FROM public.audit_events
         WHERE event_type = 'security.admin.impersonation.started'
           AND outcome = 'succeeded' AND reason = 'support.case_42'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(succeeded.get::<String, _>("actor_kind"), "user");
    assert_eq!(
        succeeded.get::<Uuid, _>("actor_subject_id"),
        target_principal.subject_id.as_uuid()
    );
    assert_eq!(
        succeeded.get::<Uuid, _>("subject_id"),
        target_principal.subject_id.as_uuid()
    );
    assert_eq!(
        succeeded.get::<Uuid, _>("impersonator_subject_id"),
        administrator.subject_id.as_uuid()
    );
    assert_eq!(
        succeeded.get::<Option<Uuid>, _>("effective_tenant_id"),
        None
    );
    assert_eq!(
        succeeded.get::<String, _>("action"),
        "admin:impersonation:start"
    );
    assert_eq!(succeeded.get::<String, _>("resource_kind"), "admin_user");
    assert_eq!(succeeded.get::<String, _>("outcome"), "succeeded");
    assert_eq!(
        succeeded.get::<Uuid, _>("request_id"),
        lineage().request_id.as_uuid()
    );
    assert_eq!(
        succeeded.get::<Uuid, _>("correlation_id"),
        lineage().correlation_id.as_uuid()
    );
    assert_eq!(succeeded.get::<String, _>("reason"), "support.case_42");
    assert_eq!(
        succeeded.get::<serde_json::Value, _>("metadata"),
        serde_json::json!({"interactive": true})
    );

    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.audit_events
             WHERE event_type = 'security.admin.identity_action'
               AND action = 'admin:user:read' AND outcome = 'succeeded'"
        )
        .fetch_one(&mut *connection)
        .await?,
        1
    );
    let mismatched_audit = sqlx::query(
        "SELECT actor_subject_id, impersonator_subject_id
         FROM public.audit_events
         WHERE event_type = 'security.admin.identity_action'
           AND outcome = 'denied' AND reason = 'admin.context_mismatch'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        mismatched_audit.get::<Uuid, _>("actor_subject_id"),
        intruder.subject_id.as_uuid()
    );
    assert_eq!(
        mismatched_audit.get::<Option<Uuid>, _>("impersonator_subject_id"),
        None
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.audit_events
             WHERE event_type = 'security.admin.impersonation.ended'
               AND outcome = 'succeeded' AND reason = 'support.case_42'"
        )
        .fetch_one(&mut *connection)
        .await?,
        1
    );

    let denied = service(
        now,
        PostgresAuditSink::default(),
        AuthorizationContext::default(),
        target_principal.clone(),
    )?
    .start_impersonation(
        &database.pool,
        &administrator,
        target,
        AuditReasonCode::new("support.case_43")?,
        Duration::from_mins(15),
        lineage(),
    )
    .await;
    assert_eq!(
        denied,
        Err(AdminError::AuthorizationDenied(DenyReason::NotEntitled))
    );
    let denied_row = sqlx::query(
        "SELECT actor_subject_id, subject_id, impersonator_subject_id, outcome, reason
         FROM public.audit_events
         WHERE event_type = 'security.admin.impersonation.started'
           AND outcome = 'denied'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        denied_row.get::<Uuid, _>("actor_subject_id"),
        administrator.subject_id.as_uuid()
    );
    assert_eq!(
        denied_row.get::<Uuid, _>("subject_id"),
        target_principal.subject_id.as_uuid()
    );
    assert_eq!(
        denied_row.get::<Option<Uuid>, _>("impersonator_subject_id"),
        None
    );
    assert_eq!(denied_row.get::<String, _>("outcome"), "denied");
    assert_eq!(
        denied_row.get::<String, _>("reason"),
        "authorization.denied"
    );

    let unresolved = service(
        now,
        PostgresAuditSink::default(),
        authorized.clone(),
        target_principal.clone(),
    )?
    .start_impersonation(
        &database.pool,
        &administrator,
        ImpersonationTarget::global(SubjectId::new()),
        AuditReasonCode::new("support.case_45")?,
        Duration::from_mins(15),
        lineage(),
    )
    .await;
    assert_eq!(unresolved, Err(AdminError::TargetUnavailable));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.audit_events
             WHERE event_type = 'security.admin.impersonation.started'
               AND outcome = 'denied' AND reason = 'admin.target_unavailable'"
        )
        .fetch_one(&mut *connection)
        .await?,
        1
    );

    let before_disabled = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.audit_events")
        .fetch_one(&mut *connection)
        .await?;
    let disabled = service(
        now,
        PostgresAuditSink::new(AuditConfig { enabled: false }),
        authorized,
        target_principal,
    )?
    .start_impersonation(
        &database.pool,
        &administrator,
        target,
        AuditReasonCode::new("support.case_44")?,
        Duration::from_mins(15),
        lineage(),
    )
    .await;
    assert_eq!(disabled, Err(AdminError::AuditDisabled));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.audit_events")
            .fetch_one(&mut *connection)
            .await?,
        before_disabled
    );

    drop(connection);
    database.pool.close().await?;
    database.fixture.cleanup().await?;
    Ok(())
}
