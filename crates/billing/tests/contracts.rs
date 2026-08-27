//! Provider adapter and billing value contract tests.

use std::{error::Error, sync::Arc};

use omnius_auth_core::TenantId;
use omnius_billing::{
    BillingProviderAdapter, BillingStanding, CurrencyCode, EntitlementGrant, EntitlementKey,
    EntitlementValue, FakeBillingAdapter, MeterKey, NewUsageRecord, PlanDefinition, PlanKey,
    ProviderAdapterError, ProviderCustomer, ProviderId, ProviderInvoice, ProviderObjectId,
    ProviderRevision, ProviderSnapshot, ProviderStateFacts, ProviderSubscription,
    ProviderUsageRequest, UsageIdempotencyKey, UsageRecordId,
};
use time::OffsetDateTime;

fn empty_snapshot(
    tenant_id: TenantId,
    provider: ProviderId,
    revision: u64,
) -> Result<ProviderSnapshot, Box<dyn Error>> {
    let customer_id = ProviderObjectId::parse("customer_fixture")?;
    Ok(ProviderSnapshot::new(
        tenant_id,
        provider,
        ProviderRevision::new(revision)?,
        OffsetDateTime::now_utc(),
        ProviderCustomer::new(customer_id, ProviderStateFacts::default()),
        Vec::new(),
        Vec::new(),
    )?)
}

#[test]
fn provider_identifiers_are_bounded_without_provider_specific_facade() {
    assert!(ProviderId::parse("fixture.billing").is_ok());
    assert!(ProviderId::parse("Stripe Billing").is_err());
    assert!(ProviderObjectId::parse("cus_123/region-1").is_ok());
    assert!(ProviderObjectId::parse("x".repeat(256)).is_err());
}

#[test]
fn plan_rejects_duplicate_entitlement_keys() -> Result<(), Box<dyn Error>> {
    let key = EntitlementKey::parse("projects.limit")?;
    let first = EntitlementGrant::new(key.clone(), EntitlementValue::Limit(5))?;
    let second = EntitlementGrant::new(key, EntitlementValue::Limit(10))?;
    let result = PlanDefinition::new(PlanKey::parse("pro")?, true, vec![first, second]);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn snapshot_rejects_subscription_for_another_customer() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let provider = ProviderId::parse("fixture")?;
    let customer = ProviderCustomer::new(
        ProviderObjectId::parse("customer_one")?,
        ProviderStateFacts::default(),
    );
    let subscription = ProviderSubscription::new(
        ProviderObjectId::parse("subscription_one")?,
        ProviderObjectId::parse("customer_two")?,
        ProviderObjectId::parse("price_pro")?,
        BillingStanding::InGoodStanding,
        None,
        None,
        ProviderStateFacts::default(),
    )?;
    let result = ProviderSnapshot::new(
        tenant_id,
        provider,
        ProviderRevision::new(1)?,
        OffsetDateTime::now_utc(),
        customer,
        vec![subscription],
        Vec::new(),
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn invoice_rejects_amount_outside_postgres_range() -> Result<(), Box<dyn Error>> {
    let result = ProviderInvoice::new(
        ProviderObjectId::parse("invoice_one")?,
        ProviderObjectId::parse("customer_one")?,
        u64::MAX,
        CurrencyCode::parse("USD")?,
        None,
        None,
        ProviderStateFacts::default(),
    );
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn fake_adapter_replays_identical_usage_and_rejects_conflicting_reuse()
-> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let provider = ProviderId::parse("fixture")?;
    let fake = Arc::new(FakeBillingAdapter::new(provider.clone()));
    fake.put_snapshot(empty_snapshot(tenant_id, provider, 1)?)?;
    let occurred_at = OffsetDateTime::now_utc();
    let usage = NewUsageRecord::new(
        MeterKey::parse("api.requests")?,
        UsageIdempotencyKey::parse("usage-key-one")?,
        3,
        occurred_at,
    )?;
    let record_id = UsageRecordId::new();
    let request = ProviderUsageRequest::new(tenant_id, record_id, &usage);
    let first = fake.submit_usage(&request).await?;
    let second = fake.submit_usage(&request).await?;
    assert_eq!(first, second);

    let conflicting = NewUsageRecord::new(
        MeterKey::parse("api.requests")?,
        UsageIdempotencyKey::parse("usage-key-one")?,
        4,
        occurred_at,
    )?;
    let Err(error) = fake
        .submit_usage(&ProviderUsageRequest::new(
            tenant_id,
            record_id,
            &conflicting,
        ))
        .await
    else {
        return Err("conflicting fake provider usage was accepted".into());
    };
    assert!(matches!(error, ProviderAdapterError::Permanent(_)));
    assert_eq!(fake.submitted_usage_count()?, 1);
    Ok(())
}
