//! Bounded concurrent realtime connection and subscription registry contracts.

use std::{error::Error, sync::Barrier, thread};

use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_realtime_core::{
    ConnectionRegistry, ConnectionState, MAX_CONNECTIONS, RegistryConfig, RegistryConfigError,
    RegistryError, RevocationReason, SubscriptionId, SubscriptionState, Topic,
};
use time::OffsetDateTime;
use uuid::Uuid;

const SUBJECT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const SUBJECT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);
const TENANT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const TENANT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0012);

fn principal(subject: Uuid, tenant: Uuid) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::from_uuid(subject)?,
        PrincipalKind::User,
        Some(TenantId::from_uuid(tenant)?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

#[test]
fn configuration_rejects_zero_inconsistent_and_excessive_capacities() {
    assert_eq!(
        RegistryConfig::new(0, 1, 1),
        Err(RegistryConfigError::ZeroCapacity)
    );
    assert_eq!(
        RegistryConfig::new(1, 1, 2),
        Err(RegistryConfigError::PerConnectionExceedsTotal)
    );
    assert_eq!(
        RegistryConfig::new(MAX_CONNECTIONS + 1, 1, 1),
        Err(RegistryConfigError::ExceedsHardLimit)
    );
}

#[test]
fn lifecycle_and_indexes_remain_tenant_isolated_and_consistent() -> Result<(), Box<dyn Error>> {
    let registry = ConnectionRegistry::new(RegistryConfig::new(4, 8, 4)?);
    let tenant_one = TenantId::from_uuid(TENANT_ONE)?;
    let tenant_two = TenantId::from_uuid(TENANT_TWO)?;
    let first = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    let second = registry.register(principal(SUBJECT_TWO, TENANT_TWO)?)?;
    assert_eq!(first.state(), ConnectionState::Registered);
    registry.activate(first.id())?;
    registry.activate(second.id())?;

    let topic = Topic::new("orders/changed")?;
    let first_subscription = SubscriptionId::new();
    let second_subscription = SubscriptionId::new();
    registry.add_subscription(
        first.id(),
        first_subscription,
        tenant_one,
        topic.clone(),
        Some("cursor-one".parse()?),
    )?;
    registry.add_subscription(
        second.id(),
        second_subscription,
        tenant_two,
        topic.clone(),
        None,
    )?;

    let mut first_matches = registry.subscriptions_for_topic(tenant_one, &topic);
    let mut second_matches = registry.subscriptions_for_topic(tenant_two, &topic);
    let first_match = first_matches
        .next_subscription()?
        .ok_or("missing first subscription")?;
    let second_match = second_matches
        .next_subscription()?
        .ok_or("missing second subscription")?;
    assert_eq!(first_match.id(), first_subscription);
    assert_eq!(first_match.subject_id(), SubjectId::from_uuid(SUBJECT_ONE)?);
    assert!(first_matches.next_subscription()?.is_none());
    assert_eq!(second_match.id(), second_subscription);
    assert!(second_matches.next_subscription()?.is_none());

    assert_eq!(
        registry.add_subscription(
            first.id(),
            first_subscription,
            tenant_one,
            topic.clone(),
            Some("cursor-one".parse()?),
        ),
        Err(RegistryError::DuplicateSubscription)
    );
    assert_eq!(
        registry.add_subscription(
            second.id(),
            first_subscription,
            tenant_two,
            topic.clone(),
            None,
        ),
        Err(RegistryError::SubscriptionConflict)
    );

    let intent =
        registry.revoke_subscription(first_subscription, RevocationReason::MembershipChanged)?;
    assert_eq!(intent.connection_id(), first.id());
    assert_eq!(
        registry
            .subscription(first_subscription)?
            .map(|value| value.state()),
        Some(SubscriptionState::Revoked)
    );
    assert!(
        registry
            .subscriptions_for_topic(tenant_one, &topic)
            .next_subscription()?
            .is_none()
    );
    assert_eq!(
        registry.revoke_subscription(first_subscription, RevocationReason::MembershipChanged,),
        Err(RegistryError::InvalidState)
    );

    let removed = registry.remove_subscription(first.id(), first_subscription)?;
    assert_eq!(removed.state(), SubscriptionState::Removed);
    assert_eq!(registry.subscription(first_subscription)?, None);
    assert_eq!(registry.subscription_count()?, 1);

    assert_eq!(
        registry.begin_close(second.id())?.state(),
        ConnectionState::Closing
    );
    assert_eq!(registry.close(second.id())?, ConnectionState::Closed);
    assert_eq!(registry.close(second.id())?, ConnectionState::Closed);
    assert_eq!(registry.connection(second.id())?, None);
    assert_eq!(registry.subscription_count()?, 0);
    assert!(
        registry
            .subscriptions_for_topic(tenant_two, &topic)
            .next_subscription()?
            .is_none()
    );
    Ok(())
}

#[test]
fn foreign_subscription_lookup_and_removal_do_not_leak_ownership() -> Result<(), Box<dyn Error>> {
    let registry = ConnectionRegistry::new(RegistryConfig::new(2, 2, 1)?);
    let tenant_one = TenantId::from_uuid(TENANT_ONE)?;
    let first = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    let second = registry.register(principal(SUBJECT_TWO, TENANT_TWO)?)?;
    registry.activate(first.id())?;
    registry.activate(second.id())?;
    let subscription_id = SubscriptionId::new();
    registry.add_subscription(
        first.id(),
        subscription_id,
        tenant_one,
        Topic::new("private")?,
        None,
    )?;

    assert_eq!(
        registry.subscription_for_connection(second.id(), subscription_id)?,
        None
    );
    assert_eq!(
        registry.remove_subscription(second.id(), subscription_id),
        Err(RegistryError::SubscriptionNotFound)
    );
    assert_eq!(registry.subscription_count()?, 1);
    Ok(())
}

#[test]
fn stale_authorized_snapshot_cannot_remove_recreated_subscription() -> Result<(), Box<dyn Error>> {
    let registry = ConnectionRegistry::new(RegistryConfig::new(1, 2, 2)?);
    let tenant = TenantId::from_uuid(TENANT_ONE)?;
    let connection = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    registry.activate(connection.id())?;
    let subscription_id = SubscriptionId::new();
    let stale = registry.add_subscription(
        connection.id(),
        subscription_id,
        tenant,
        Topic::new("old-resource")?,
        None,
    )?;
    registry.remove_subscription(connection.id(), subscription_id)?;
    let current = registry.add_subscription(
        connection.id(),
        subscription_id,
        tenant,
        Topic::new("new-resource")?,
        None,
    )?;

    assert_eq!(
        registry.remove_subscription_if_current(connection.id(), &stale),
        Err(RegistryError::SubscriptionConflict)
    );
    assert_eq!(
        registry
            .subscription_for_connection(connection.id(), subscription_id)?
            .map(|subscription| subscription.topic().as_str().to_owned()),
        Some("new-resource".to_owned())
    );
    assert_ne!(stale.generation(), current.generation());
    assert!(!registry.is_subscription_current_active(subscription_id, stale.generation())?);
    assert!(registry.is_subscription_current_active(subscription_id, current.generation())?);
    registry.begin_close(connection.id())?;
    assert!(!registry.is_subscription_current_active(subscription_id, current.generation())?);
    assert_eq!(registry.subscription_count()?, 1);
    Ok(())
}

#[test]
fn connection_and_subscription_capacities_fail_without_partial_mutation()
-> Result<(), Box<dyn Error>> {
    let registry = ConnectionRegistry::new(RegistryConfig::new(2, 2, 1)?);
    let first = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    let second = registry.register(principal(SUBJECT_TWO, TENANT_TWO)?)?;
    assert_eq!(
        registry.register(principal(SUBJECT_ONE, TENANT_ONE)?),
        Err(RegistryError::ConnectionCapacity)
    );
    registry.activate(first.id())?;
    registry.activate(second.id())?;
    let tenant_one = TenantId::from_uuid(TENANT_ONE)?;
    let tenant_two = TenantId::from_uuid(TENANT_TWO)?;
    registry.add_subscription(
        first.id(),
        SubscriptionId::new(),
        tenant_one,
        Topic::new("one")?,
        None,
    )?;
    assert_eq!(
        registry.add_subscription(
            first.id(),
            SubscriptionId::new(),
            tenant_one,
            Topic::new("two")?,
            None,
        ),
        Err(RegistryError::PerConnectionSubscriptionCapacity)
    );
    registry.add_subscription(
        second.id(),
        SubscriptionId::new(),
        tenant_two,
        Topic::new("two")?,
        None,
    )?;
    assert_eq!(registry.subscription_count()?, 2);
    assert_eq!(registry.connection_count()?, 2);
    Ok(())
}

#[test]
fn registry_rejects_subscription_tenant_that_differs_from_bound_principal()
-> Result<(), Box<dyn Error>> {
    let registry = ConnectionRegistry::new(RegistryConfig::new(1, 1, 1)?);
    let connection = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    registry.activate(connection.id())?;
    let tenant_two = TenantId::from_uuid(TENANT_TWO)?;

    assert_eq!(
        registry.add_subscription(
            connection.id(),
            SubscriptionId::new(),
            tenant_two,
            Topic::new("tenant-two/private")?,
            None,
        ),
        Err(RegistryError::TenantMismatch)
    );
    assert_eq!(registry.subscription_count()?, 0);
    Ok(())
}

#[test]
fn concurrent_registration_never_exceeds_capacity() -> Result<(), Box<dyn Error>> {
    const LIMIT: usize = 8;
    const ATTEMPTS: usize = 32;
    let registry = ConnectionRegistry::new(RegistryConfig::new(LIMIT, 64, 8)?);
    let principal = principal(SUBJECT_ONE, TENANT_ONE)?;
    let barrier = std::sync::Arc::new(Barrier::new(ATTEMPTS));
    let mut handles = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS {
        let registry = registry.clone();
        let principal = principal.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let _ = barrier.wait();
            registry.register(principal)
        }));
    }

    let successes = handles
        .into_iter()
        .map(thread::JoinHandle::join)
        .filter(|result| matches!(result, Ok(Ok(_))))
        .count();
    assert_eq!(successes, LIMIT);
    assert_eq!(registry.connection_count()?, LIMIT);
    Ok(())
}

#[test]
fn concurrent_subscription_creation_never_exceeds_total_capacity() -> Result<(), Box<dyn Error>> {
    const LIMIT: usize = 16;
    const ATTEMPTS: usize = 48;
    let registry = ConnectionRegistry::new(RegistryConfig::new(1, LIMIT, LIMIT)?);
    let connection = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    registry.activate(connection.id())?;
    let connection_id = connection.id();
    let tenant = TenantId::from_uuid(TENANT_ONE)?;
    let topic = Topic::new("concurrent")?;
    let barrier = std::sync::Arc::new(Barrier::new(ATTEMPTS));
    let mut handles = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS {
        let registry = registry.clone();
        let topic = topic.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let _ = barrier.wait();
            registry.add_subscription(connection_id, SubscriptionId::new(), tenant, topic, None)
        }));
    }

    let successes = handles
        .into_iter()
        .map(thread::JoinHandle::join)
        .filter(|result| matches!(result, Ok(Ok(_))))
        .count();
    assert_eq!(successes, LIMIT);
    assert_eq!(registry.subscription_count()?, LIMIT);
    let mut matches = registry.subscriptions_for_topic(tenant, &Topic::new("concurrent")?);
    let mut match_count = 0;
    while matches.next_subscription()?.is_some() {
        match_count += 1;
    }
    assert_eq!(match_count, LIMIT);
    Ok(())
}
