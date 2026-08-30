use std::{error::Error, sync::Arc};

use omnius_llm_core::Usage;

use crate::{
    ApiKeyId, BudgetCeilings, BudgetDimension, BudgetMetric, BudgetPolicy, BudgetScope,
    BudgetValue, CostMicrounits, IdempotencyKey, JobId, LedgerError, LedgerVersion, ModelId,
    OperationId, PrincipalId, ProviderId, RequestFingerprint, Reservation, ReservationId,
    ReservationRequest, ReservationState, RouteId, TenantId, ToolId, UsageAmount, UsageBreakdown,
    UsageEvidence, UsageLedger, UsageLedgerRepository, UsageStatus, UsageVector,
    testing::InMemoryUsageLedgerRepository,
};

fn primary_usage(requests: u64, tokens: u64, cost: u64) -> UsageBreakdown {
    UsageBreakdown::primary(
        UsageVector::zero()
            .with_requests(UsageAmount::new(requests))
            .with_concurrent_streams(UsageAmount::ONE)
            .with_tokens(UsageAmount::new(tokens))
            .with_cost(CostMicrounits::new(cost)),
    )
}

fn tenant_scope(value: &str) -> Result<BudgetScope, Box<dyn Error>> {
    Ok(BudgetScope::new(TenantId::new(value)?))
}

fn full_scope(value: &str) -> Result<BudgetScope, Box<dyn Error>> {
    Ok(tenant_scope(value)?
        .with_principal(PrincipalId::new("principal")?)
        .with_api_key(ApiKeyId::new("api-key")?)
        .with_provider(ProviderId::new("provider")?)
        .with_model(ModelId::new("model")?)
        .with_route(RouteId::new("route:v1")?)
        .with_tool(ToolId::new("tool")?)
        .with_operation(OperationId::new("operation")?)
        .with_job(JobId::new("job")?))
}

fn request(
    id: &str,
    key: &str,
    fingerprint: u8,
    scope: BudgetScope,
    estimate: UsageBreakdown,
    policies: Vec<BudgetPolicy>,
) -> Result<ReservationRequest, Box<dyn Error>> {
    Ok(ReservationRequest::new(
        ReservationId::new(id)?,
        IdempotencyKey::new(key)?,
        RequestFingerprint::new([fingerprint; 32]),
        scope,
        estimate,
        policies,
    )?)
}

fn tenant_request_policy(maximum: u64) -> BudgetPolicy {
    BudgetPolicy::new(
        BudgetDimension::Tenant,
        BudgetCeilings::none().with_requests(UsageAmount::new(maximum)),
    )
}

#[test]
fn exact_amounts_reject_overflow_and_underflow() {
    assert!(UsageAmount::MAX.checked_add(UsageAmount::ONE).is_err());
    assert!(
        CostMicrounits::MAX
            .checked_add(CostMicrounits::new(1))
            .is_err()
    );
    assert!(UsageAmount::ZERO.checked_sub(UsageAmount::ONE).is_err());
    let overflow = UsageBreakdown::new(
        UsageVector::zero().with_tokens(UsageAmount::MAX),
        UsageVector::zero().with_tokens(UsageAmount::ONE),
        UsageVector::zero(),
        UsageVector::zero(),
    );
    assert!(overflow.checked_total().is_err());
}

#[test]
fn reservation_estimates_require_a_dispatched_request() -> Result<(), Box<dyn Error>> {
    let estimate = UsageBreakdown::primary(
        UsageVector::zero()
            .with_tokens(UsageAmount::new(10))
            .with_cost(CostMicrounits::new(100)),
    );
    let result = ReservationRequest::new(
        ReservationId::new("reservation-without-request")?,
        IdempotencyKey::new("key-without-request")?,
        RequestFingerprint::new([33; 32]),
        tenant_scope("tenant-without-request")?,
        estimate,
        vec![tenant_request_policy(2)],
    );

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn zero_and_exhausted_budgets_reject_before_dispatch() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(Arc::clone(&repository));
    let zero = request(
        "reservation-zero",
        "key-zero",
        1,
        tenant_scope("tenant-a")?,
        primary_usage(1, 0, 0),
        vec![tenant_request_policy(0)],
    )?;
    let zero_result = ledger.reserve(&zero).await;
    assert!(matches!(
        zero_result,
        Err(LedgerError::BudgetExhausted(exhaustion))
            if exhaustion.dimension() == BudgetDimension::Tenant
                && exhaustion.metric() == BudgetMetric::Requests
                && exhaustion.current() == BudgetValue::Usage(UsageAmount::ZERO)
                && exhaustion.requested() == BudgetValue::Usage(UsageAmount::ONE)
                && exhaustion.maximum() == BudgetValue::Usage(UsageAmount::ZERO)
    ));
    assert!(
        repository
            .reservations_for_tenant(zero.scope().tenant())?
            .is_empty()
    );

    let first = request(
        "reservation-first",
        "key-first",
        2,
        tenant_scope("tenant-a")?,
        primary_usage(1, 0, 0),
        vec![tenant_request_policy(1)],
    )?;
    ledger.reserve(&first).await?;
    let second = request(
        "reservation-second",
        "key-second",
        3,
        tenant_scope("tenant-a")?,
        primary_usage(1, 0, 0),
        vec![tenant_request_policy(1)],
    )?;
    assert!(matches!(
        ledger.reserve(&second).await,
        Err(LedgerError::BudgetExhausted(exhaustion))
            if exhaustion.current() == BudgetValue::Usage(UsageAmount::ONE)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_duplicate_reservation_is_inserted_once() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(Arc::clone(&repository));
    let reservation = request(
        "reservation-duplicate",
        "key-duplicate",
        4,
        tenant_scope("tenant-duplicate")?,
        primary_usage(1, 5, 9),
        vec![tenant_request_policy(1)],
    )?;
    let first_ledger = ledger.clone();
    let first_request = reservation.clone();
    let first = tokio::spawn(async move { first_ledger.reserve(&first_request).await });
    let second_ledger = ledger.clone();
    let second_request = reservation.clone();
    let second = tokio::spawn(async move { second_ledger.reserve(&second_request).await });
    let first = first.await??;
    let second = second.await??;

    assert_ne!(first.replayed(), second.replayed());
    assert_eq!(
        repository
            .reservations_for_tenant(reservation.scope().tenant())?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn public_adapter_constructors_enforce_lifecycle_versions() -> Result<(), Box<dyn Error>> {
    let command = request(
        "reservation-restore",
        "key-restore",
        31,
        tenant_scope("tenant-restore")?,
        primary_usage(1, 2, 3),
        vec![tenant_request_policy(1)],
    )?;
    let (initial, event) = Reservation::initial(&command)?;
    assert_eq!(initial.version(), LedgerVersion::INITIAL);
    assert_eq!(event.version(), LedgerVersion::INITIAL);
    assert!(
        Reservation::restore(
            command.clone(),
            ReservationState::Released,
            LedgerVersion::new(2),
        )
        .is_err()
    );
    let restored =
        Reservation::restore(command, ReservationState::Released, LedgerVersion::new(1))?;
    assert_eq!(restored.version(), LedgerVersion::new(1));
    Ok(())
}

#[tokio::test]
async fn conflicting_idempotency_replay_fails_closed() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let original = request(
        "reservation-original",
        "shared-key",
        5,
        tenant_scope("tenant-conflict")?,
        primary_usage(1, 5, 9),
        vec![tenant_request_policy(2)],
    )?;
    let conflict = request(
        "reservation-other",
        "shared-key",
        5,
        tenant_scope("tenant-conflict")?,
        primary_usage(1, 5, 9),
        vec![tenant_request_policy(3)],
    )?;
    ledger.reserve(&original).await?;

    assert!(matches!(
        ledger.reserve(&conflict).await,
        Err(LedgerError::IdempotencyConflict)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_release_race_has_one_winner() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let reservation = request(
        "reservation-race",
        "key-race",
        7,
        tenant_scope("tenant-race")?,
        primary_usage(1, 5, 9),
        vec![tenant_request_policy(2)],
    )?;
    ledger.reserve(&reservation).await?;
    let tenant = reservation.scope().tenant().clone();
    let id = reservation.id().clone();
    let commit_ledger = ledger.clone();
    let commit_tenant = tenant.clone();
    let commit_id = id.clone();
    let commit = tokio::spawn(async move {
        commit_ledger
            .commit(&commit_tenant, &commit_id, UsageEvidence::Missing)
            .await
    });
    let release_ledger = ledger.clone();
    let release = tokio::spawn(async move { release_ledger.release(&tenant, &id).await });
    let commit = commit.await?;
    let release = release.await?;

    assert_ne!(commit.is_ok(), release.is_ok());
    assert!(matches!(
        commit.as_ref().err().or_else(|| release.as_ref().err()),
        Some(LedgerError::TransitionConflict)
    ));
    Ok(())
}

#[tokio::test]
async fn actual_usage_cannot_erase_dispatched_request_accounting() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let reservation = request(
        "reservation-underreported",
        "key-underreported",
        31,
        tenant_scope("tenant-underreported")?,
        primary_usage(1, 10, 100),
        vec![tenant_request_policy(2)],
    )?;
    ledger.reserve(&reservation).await?;
    let underreported = UsageBreakdown::primary(
        UsageVector::zero()
            .with_tokens(UsageAmount::new(10))
            .with_cost(CostMicrounits::new(100)),
    );

    assert!(matches!(
        ledger
            .commit(
                reservation.scope().tenant(),
                reservation.id(),
                UsageEvidence::Actual(underreported),
            )
            .await,
        Err(LedgerError::UnderreportedUsage)
    ));
    let retry_estimate = UsageBreakdown::new(
        UsageVector::zero()
            .with_requests(UsageAmount::new(1))
            .with_tokens(UsageAmount::new(10))
            .with_cost(CostMicrounits::new(100)),
        UsageVector::zero()
            .with_requests(UsageAmount::new(2))
            .with_tokens(UsageAmount::new(20))
            .with_cost(CostMicrounits::new(200)),
        UsageVector::zero(),
        UsageVector::zero(),
    );
    let overestimated = request(
        "reservation-overestimated-retries",
        "key-overestimated-retries",
        32,
        tenant_scope("tenant-underreported")?,
        retry_estimate,
        vec![tenant_request_policy(10)],
    )?;
    ledger.reserve(&overestimated).await?;
    ledger
        .commit(
            overestimated.scope().tenant(),
            overestimated.id(),
            UsageEvidence::Actual(primary_usage(1, 10, 100)),
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn reconciliation_records_positive_and_negative_exact_adjustments()
-> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let policy = BudgetPolicy::new(
        BudgetDimension::Tenant,
        BudgetCeilings::none().with_cost(CostMicrounits::new(1_000)),
    );
    let positive = request(
        "reservation-positive",
        "key-positive",
        8,
        tenant_scope("tenant-reconcile")?,
        primary_usage(1, 10, 100),
        vec![policy.clone()],
    )?;
    ledger.reserve(&positive).await?;
    ledger
        .commit(
            positive.scope().tenant(),
            positive.id(),
            UsageEvidence::Missing,
        )
        .await?;
    let positive_result = ledger
        .reconcile(
            positive.scope().tenant(),
            positive.id(),
            primary_usage(1, 15, 150),
        )
        .await?;
    assert_eq!(positive_result.event().adjustment().cost().get(), 50);

    let negative = request(
        "reservation-negative",
        "key-negative",
        9,
        tenant_scope("tenant-reconcile")?,
        primary_usage(1, 10, 100),
        vec![policy],
    )?;
    ledger.reserve(&negative).await?;
    ledger
        .commit(
            negative.scope().tenant(),
            negative.id(),
            UsageEvidence::Missing,
        )
        .await?;
    let negative_result = ledger
        .reconcile(
            negative.scope().tenant(),
            negative.id(),
            primary_usage(1, 8, 60),
        )
        .await?;
    assert_eq!(negative_result.event().adjustment().cost().get(), -40);
    Ok(())
}

#[tokio::test]
async fn positive_actual_overage_exhausts_later_reservations() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let policy = BudgetPolicy::new(
        BudgetDimension::Tenant,
        BudgetCeilings::none().with_cost(CostMicrounits::new(120)),
    );
    let original = request(
        "reservation-overage",
        "key-overage",
        10,
        tenant_scope("tenant-overage")?,
        primary_usage(1, 10, 100),
        vec![policy.clone()],
    )?;
    ledger.reserve(&original).await?;
    ledger
        .commit(
            original.scope().tenant(),
            original.id(),
            UsageEvidence::Missing,
        )
        .await?;
    ledger
        .reconcile(
            original.scope().tenant(),
            original.id(),
            primary_usage(1, 10, 150),
        )
        .await?;
    let later = request(
        "reservation-after-overage",
        "key-after-overage",
        11,
        tenant_scope("tenant-overage")?,
        primary_usage(1, 1, 1),
        vec![policy],
    )?;

    assert!(matches!(
        ledger.reserve(&later).await,
        Err(LedgerError::BudgetExhausted(exhaustion))
            if exhaustion.metric() == BudgetMetric::CostMicrounits
    ));
    Ok(())
}

#[tokio::test]
async fn missing_and_ambiguous_usage_remain_explicit_and_conservative() -> Result<(), Box<dyn Error>>
{
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let missing = request(
        "reservation-missing",
        "key-missing",
        12,
        tenant_scope("tenant-evidence")?,
        primary_usage(1, 10, 100),
        vec![tenant_request_policy(10)],
    )?;
    ledger.reserve(&missing).await?;
    let missing_result = ledger
        .commit(
            missing.scope().tenant(),
            missing.id(),
            UsageEvidence::Missing,
        )
        .await?;
    assert_eq!(missing_result.event().usage_status(), UsageStatus::Missing);
    assert_eq!(
        missing_result
            .event()
            .effective_usage()
            .primary_usage()
            .cost(),
        CostMicrounits::new(100)
    );

    let ambiguous = request(
        "reservation-ambiguous",
        "key-ambiguous",
        13,
        tenant_scope("tenant-evidence")?,
        primary_usage(1, 10, 100),
        vec![tenant_request_policy(10)],
    )?;
    ledger.reserve(&ambiguous).await?;
    let ambiguous_result = ledger
        .commit(
            ambiguous.scope().tenant(),
            ambiguous.id(),
            UsageEvidence::Ambiguous(primary_usage(1, 20, 70)),
        )
        .await?;
    let effective = ambiguous_result.event().effective_usage().primary_usage();
    assert_eq!(
        ambiguous_result.event().usage_status(),
        UsageStatus::Ambiguous
    );
    assert_eq!(effective.cost(), CostMicrounits::new(100));
    assert_eq!(effective.tokens(), UsageAmount::new(20));
    assert_eq!(effective.concurrent_streams(), UsageAmount::ZERO);
    Ok(())
}

#[tokio::test]
async fn identical_keys_and_ids_are_isolated_by_tenant() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(Arc::clone(&repository));
    let tenant_a = request(
        "shared-reservation",
        "shared-key",
        14,
        tenant_scope("tenant-isolated-a")?,
        primary_usage(1, 0, 0),
        vec![tenant_request_policy(1)],
    )?;
    let tenant_b = request(
        "shared-reservation",
        "shared-key",
        14,
        tenant_scope("tenant-isolated-b")?,
        primary_usage(1, 0, 0),
        vec![tenant_request_policy(1)],
    )?;
    ledger.reserve(&tenant_a).await?;
    ledger.reserve(&tenant_b).await?;

    assert_eq!(
        repository
            .reservations_for_tenant(tenant_a.scope().tenant())?
            .len(),
        1
    );
    assert_eq!(
        repository
            .reservations_for_tenant(tenant_b.scope().tenant())?
            .len(),
        1
    );
    assert!(
        repository
            .load(&TenantId::new("tenant-third")?, tenant_a.id())
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn every_declared_budget_dimension_enforces_its_own_hard_ceiling()
-> Result<(), Box<dyn Error>> {
    for (index, dimension) in [
        BudgetDimension::Tenant,
        BudgetDimension::Principal,
        BudgetDimension::ApiKey,
        BudgetDimension::Provider,
        BudgetDimension::Model,
        BudgetDimension::Route,
        BudgetDimension::Tool,
        BudgetDimension::Operation,
        BudgetDimension::Job,
    ]
    .into_iter()
    .enumerate()
    {
        let repository = Arc::new(InMemoryUsageLedgerRepository::new());
        let ledger = UsageLedger::new(repository);
        let policy = BudgetPolicy::new(
            dimension,
            BudgetCeilings::none().with_requests(UsageAmount::ONE),
        );
        let first = request(
            &format!("reservation-dimension-{index}-a"),
            &format!("key-dimension-{index}-a"),
            u8::try_from(index)?,
            full_scope(&format!("tenant-dimension-{index}"))?,
            primary_usage(1, 0, 0),
            vec![policy.clone()],
        )?;
        let second = request(
            &format!("reservation-dimension-{index}-b"),
            &format!("key-dimension-{index}-b"),
            u8::try_from(index + 32)?,
            full_scope(&format!("tenant-dimension-{index}"))?,
            primary_usage(1, 0, 0),
            vec![policy],
        )?;
        ledger.reserve(&first).await?;
        assert!(matches!(
            ledger.reserve(&second).await,
            Err(LedgerError::BudgetExhausted(exhaustion))
                if exhaustion.dimension() == dimension
        ));
    }
    Ok(())
}

#[tokio::test]
async fn retry_repair_and_tool_usage_remain_separately_attributed() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let primary = UsageVector::zero()
        .with_requests(UsageAmount::ONE)
        .with_cost(CostMicrounits::new(10));
    let retry = UsageVector::zero()
        .with_requests(UsageAmount::ONE)
        .with_cost(CostMicrounits::new(2));
    let repair = UsageVector::zero()
        .with_requests(UsageAmount::ONE)
        .with_cost(CostMicrounits::new(3));
    let tool = UsageVector::zero()
        .with_tool_calls(UsageAmount::new(2))
        .with_cost(CostMicrounits::new(4));
    let attributed = UsageBreakdown::new(primary, retry, repair, tool);
    let reservation = request(
        "reservation-attribution",
        "key-attribution",
        20,
        full_scope("tenant-attribution")?,
        attributed,
        vec![BudgetPolicy::new(
            BudgetDimension::Tenant,
            BudgetCeilings::none().with_cost(CostMicrounits::new(19)),
        )],
    )?;
    let result = ledger.reserve(&reservation).await?;
    let persisted = result.reservation().estimate();

    assert_eq!(persisted.primary_usage().cost(), CostMicrounits::new(10));
    assert_eq!(persisted.retry_usage().cost(), CostMicrounits::new(2));
    assert_eq!(persisted.repair_usage().cost(), CostMicrounits::new(3));
    assert_eq!(persisted.tool_usage().cost(), CostMicrounits::new(4));
    assert_eq!(persisted.tool_usage().tool_calls(), UsageAmount::new(2));
    assert_eq!(persisted.checked_total()?.cost(), CostMicrounits::new(19));
    Ok(())
}

#[test]
fn canonical_provider_usage_retains_missing_and_ambiguous_classification()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        UsageEvidence::from_provider_usage(&Usage::new(None, None))?,
        UsageEvidence::Missing
    );
    assert!(matches!(
        UsageEvidence::from_provider_usage(&Usage::new(Some(2), None))?,
        UsageEvidence::Ambiguous(_)
    ));
    let detailed =
        Usage::new(None, None).with_token_details(Some(5), None, None, Some(7), None, None);
    assert!(matches!(
        UsageEvidence::from_provider_usage(&detailed)?,
        UsageEvidence::Ambiguous(value)
            if value.primary_usage().tokens() == UsageAmount::new(12)
    ));
    let actual = Usage::new(Some(2), Some(3)).with_costs(None, Some(7), None);
    assert!(matches!(
        UsageEvidence::from_provider_usage(&actual)?,
        UsageEvidence::Actual(value)
            if value.primary_usage().tokens() == UsageAmount::new(5)
                && value.primary_usage().cost() == CostMicrounits::new(7)
    ));
    Ok(())
}

#[test]
fn identifier_deserialization_preserves_bounds() -> Result<(), Box<dyn Error>> {
    let valid: TenantId = serde_json::from_str("\"tenant-safe\"")?;
    assert_eq!(valid.as_str(), "tenant-safe");
    assert!(serde_json::from_str::<TenantId>("\"\"").is_err());
    let oversized = format!("\"{}\"", "a".repeat(129));
    assert!(serde_json::from_str::<TenantId>(&oversized).is_err());
    assert!(serde_json::from_str::<TenantId>("\"tenant unsafe\"").is_err());
    Ok(())
}

#[tokio::test]
async fn debug_display_audit_and_errors_redact_sensitive_values() -> Result<(), Box<dyn Error>> {
    let scope = BudgetScope::new(TenantId::new("tenant-secret-credential")?)
        .with_principal(PrincipalId::new("principal-secret")?)
        .with_provider(ProviderId::new("provider-secret")?)
        .with_model(ModelId::new("model-secret")?)
        .with_route(RouteId::new("route-secret")?)
        .with_tool(ToolId::new("tool-secret")?)
        .with_job(JobId::new("job-secret")?);
    let reservation = request(
        "reservation-secret",
        "idempotency-secret",
        99,
        scope,
        primary_usage(1, 2, 3),
        vec![tenant_request_policy(0)],
    )?;
    let repository = Arc::new(InMemoryUsageLedgerRepository::new());
    let ledger = UsageLedger::new(repository);
    let error = ledger.reserve(&reservation).await;
    let rendered = format!(
        "{reservation:?} {:?} {:?} {error:?} {}",
        reservation.scope(),
        reservation.fingerprint(),
        reservation.idempotency_key()
    );
    for secret in [
        "tenant-secret-credential",
        "principal-secret",
        "provider-secret",
        "model-secret",
        "route-secret",
        "tool-secret",
        "job-secret",
        "reservation-secret",
        "idempotency-secret",
    ] {
        assert!(!rendered.contains(secret));
    }

    let allowed = request(
        "reservation-audit-secret",
        "audit-key-secret",
        100,
        tenant_scope("tenant-audit-secret")?,
        primary_usage(1, 2, 3),
        vec![tenant_request_policy(1)],
    )?;
    let operation = ledger.reserve(&allowed).await?;
    let audit = format!("{:?}", operation.event().audit_projection());
    assert!(!audit.contains("tenant-audit-secret"));
    assert!(!audit.contains("audit-key-secret"));
    assert!(!audit.contains("reservation-audit-secret"));
    let serialized_event = serde_json::to_string(operation.event())?;
    assert!(!serialized_event.contains("tenant-audit-secret"));
    assert!(!serialized_event.contains("audit-key-secret"));
    assert!(!serialized_event.contains("reservation-audit-secret"));
    assert!(matches!(error, Err(LedgerError::BudgetExhausted(_))));
    assert!(matches!(
        operation.reservation().state(),
        ReservationState::Reserved
    ));
    Ok(())
}
