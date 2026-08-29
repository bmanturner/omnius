//! Contract tests for the distributed Redis rate limiter.

use std::{error::Error, net::IpAddr, time::Duration};

use omnius_config::DeploymentEnvironment;
use omnius_rate_limit_redis::{
    DecisionReason, FailurePolicy, PrincipalKind, RateLimitClientId, RateLimitDecision,
    RateLimitKey, RateLimitOperation, RateLimitPolicy, RateLimitPolicyError, RateLimitRequest,
    RateLimiter, RedisRateLimiter, RedisRateLimiterConfig, TrustedRateLimitContext,
};
use omnius_redis_core::{RedisCommandFamily, RedisConfig, RedisCore, RedisReconnectConfig};
use omnius_test_support::RedisFixture;
use tokio::task::JoinSet;

fn redis_config(fixture: &RedisFixture, command_timeout: Duration) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(3),
        startup_timeout: Duration::from_secs(10),
        command_timeout,
        health_timeout: Duration::from_secs(3),
        client_name: "omnius-rate-limit-integration".to_owned(),
        key_prefix: fixture.namespace().replace(':', "-"),
        schema_version: "v9".to_owned(),
        max_value_bytes: 1024,
        reconnect: RedisReconnectConfig::default(),
    }
}

async fn connected(
    fixture: &RedisFixture,
    command_timeout: Duration,
) -> Result<RedisCore, Box<dyn Error>> {
    RedisCore::connect(
        &redis_config(fixture, command_timeout),
        DeploymentEnvironment::Test,
    )
    .await?
    .ok_or_else(|| std::io::Error::other("enabled Redis limiter unexpectedly disabled").into())
}

fn request(
    tenant: &str,
    principal: &str,
    resource: &str,
    policy: RateLimitPolicy,
) -> Result<RateLimitRequest, Box<dyn Error>> {
    let key = RateLimitKey::new(tenant, PrincipalKind::Account, principal, resource)?;
    Ok(RateLimitRequest::new(key, policy, 1)?)
}

async fn concurrently_allowed(
    limiter: &RedisRateLimiter,
    request: &RateLimitRequest,
    attempts: usize,
) -> Result<usize, tokio::task::JoinError> {
    let mut tasks = JoinSet::new();
    for _ in 0..attempts {
        let limiter = limiter.clone();
        let request = request.clone();
        let _ = tasks.spawn(async move { limiter.check(&request).await });
    }
    let mut allowed = 0_usize;
    while let Some(result) = tasks.join_next().await {
        if result?.is_allowed() {
            allowed += 1;
        }
    }
    Ok(allowed)
}

#[tokio::test]
async fn fixed_window_is_atomic_and_denies_after_capacity() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let limiter = RedisRateLimiter::new(redis.clone(), RedisRateLimiterConfig::default())?;
    let request = request(
        "tenant-fixed",
        "account-fixed",
        "login",
        RateLimitPolicy::fixed_window(2, Duration::from_hours(1))?,
    )?;

    let allowed = concurrently_allowed(&limiter, &request, 32).await?;

    assert_eq!(allowed, 2);
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn sliding_window_is_atomic_and_denies_after_weighted_capacity() -> Result<(), Box<dyn Error>>
{
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let limiter = RedisRateLimiter::new(redis.clone(), RedisRateLimiterConfig::default())?;
    let request = request(
        "tenant-sliding",
        "account-sliding",
        "search",
        RateLimitPolicy::sliding_window(2, Duration::from_hours(1))?,
    )?;

    let allowed = concurrently_allowed(&limiter, &request, 32).await?;

    assert_eq!(allowed, 2);
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn gcra_script_consumes_concurrent_burst_exactly_once() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let limiter = RedisRateLimiter::new(redis.clone(), RedisRateLimiterConfig::default())?;
    let request = request(
        "tenant-concurrent",
        "account-concurrent",
        "upload",
        RateLimitPolicy::gcra(1, Duration::from_mins(1), 7)?,
    )?;
    let allowed = concurrently_allowed(&limiter, &request, 32).await?;

    assert_eq!(allowed, 7);
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}
#[test]
fn gcra_rejects_rates_below_redis_clock_resolution() {
    let result = RateLimitPolicy::gcra(1_001, Duration::from_millis(1), 1);

    assert_eq!(
        result,
        Err(RateLimitPolicyError::RateExceedsClockResolution)
    );
}

#[tokio::test]
async fn tenant_principal_and_resource_inputs_produce_independent_budgets()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let limiter = RedisRateLimiter::new(redis.clone(), RedisRateLimiterConfig::default())?;
    let policy = RateLimitPolicy::gcra(1, Duration::from_hours(1), 1)?;
    let first = request("tenant-a", "account-a", "login", policy.clone())?;
    let other_principal = request("tenant-a", "account-b", "login", policy.clone())?;
    let other_tenant = request("tenant-b", "account-a", "login", policy.clone())?;
    let other_resource = request("tenant-a", "account-a", "recovery", policy)?;

    let storage_keys = [
        limiter.storage_key_for(&first)?,
        limiter.storage_key_for(&other_principal)?,
        limiter.storage_key_for(&other_tenant)?,
        limiter.storage_key_for(&other_resource)?,
    ];
    let decisions = (
        limiter.check(&first).await.is_allowed(),
        limiter.check(&first).await.is_allowed(),
        limiter.check(&other_principal).await.is_allowed(),
        limiter.check(&other_tenant).await.is_allowed(),
        limiter.check(&other_resource).await.is_allowed(),
    );

    assert_eq!(
        (
            storage_keys
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            decisions
        ),
        (4, (true, false, true, true, true))
    );
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn rate_limit_state_has_a_positive_bounded_ttl() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let limiter = RedisRateLimiter::new(redis.clone(), RedisRateLimiterConfig::default())?;
    let request = request(
        "tenant-ttl",
        "account-ttl",
        "administration",
        RateLimitPolicy::gcra(1, Duration::from_mins(1), 7)?,
    )?;
    assert!(limiter.check(&request).await.is_allowed());
    let key = limiter.storage_key_for(&request)?;
    let mut pttl = redis::cmd("PTTL");
    pttl.arg(key);
    let ttl_ms = redis
        .query::<i64>(RedisCommandFamily::RateLimit, pttl)
        .await?;

    assert!((1..=60_000).contains(&ttl_ms));
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_redis_state_fails_closed_without_echoing_state() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let limiter = RedisRateLimiter::new(redis.clone(), RedisRateLimiterConfig::default())?;
    let request = request(
        "tenant-corrupt",
        "account-corrupt",
        "api-key-management",
        RateLimitPolicy::fixed_window(3, Duration::from_mins(5))?,
    )?;
    let key = limiter.storage_key_for(&request)?;
    let mut poison = redis::cmd("SET");
    poison.arg(key).arg("secret-invalid-state");
    redis
        .query::<()>(RedisCommandFamily::RateLimit, poison)
        .await?;

    let decision = limiter.check(&request).await;

    assert_eq!(
        (
            decision.is_allowed(),
            decision.reason(),
            decision.remaining()
        ),
        (false, DecisionReason::BackendUnavailable, None)
    );
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn redis_timeout_applies_explicit_fail_closed_policy() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_millis(50)).await?;
    let limiter = RedisRateLimiter::new(
        redis.clone(),
        RedisRateLimiterConfig {
            key_buckets: 1_000_000,
            failure_policy: FailurePolicy::Closed,
        },
    )?;
    let request = request(
        "tenant-timeout",
        "account-timeout",
        "webhook-replay",
        RateLimitPolicy::fixed_window(3, Duration::from_mins(5))?,
    )?;
    let mut pause = redis::cmd("CLIENT");
    pause.arg("PAUSE").arg(500).arg("ALL");
    redis.query::<()>(RedisCommandFamily::Health, pause).await?;

    let decision = limiter.check(&request).await;

    assert_eq!(
        (decision.is_allowed(), decision.reason()),
        (false, DecisionReason::BackendUnavailable)
    );
    drop(limiter);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn deterministic_fake_captures_only_fingerprints_and_honors_availability()
-> Result<(), Box<dyn Error>> {
    let fake = omnius_rate_limit_redis::FakeRateLimiter::new(
        omnius_rate_limit_redis::FakeRateLimiterConfig::default(),
        RateLimitDecision::allow(9, Duration::from_secs(1)),
    )?;
    let request = request(
        "sensitive-tenant",
        "sensitive-principal",
        "login",
        RateLimitPolicy::fixed_window(10, Duration::from_secs(1))?,
    )?;
    let allowed = fake.check(&request).await;
    fake.set_available(false)?;
    let unavailable = fake.check(&request).await;
    let calls = fake.calls()?;
    let captured_debug = format!("{:?}", calls[0]);

    assert_eq!(
        (
            allowed.is_allowed(),
            unavailable.reason(),
            calls.len(),
            calls[0].fingerprint() == request.key().fingerprint(),
            captured_debug.contains("[REDACTED]")
        ),
        (true, DecisionReason::BackendUnavailable, 1, true, true)
    );
    Ok(())
}

fn trusted_context(
    address: &str,
    client_id: Option<&str>,
) -> Result<TrustedRateLimitContext, Box<dyn Error>> {
    let context = TrustedRateLimitContext::new(address.parse::<IpAddr>()?);
    match client_id {
        Some(client_id) => Ok(context.with_oauth_client_id(RateLimitClientId::new(client_id)?)),
        None => Ok(context),
    }
}

#[test]
fn oauth_operations_have_distinct_stable_policy_names() {
    assert_eq!(
        [
            RateLimitOperation::OAuthAuthorize.as_str(),
            RateLimitOperation::OAuthToken.as_str(),
            RateLimitOperation::OAuthClientRegistration.as_str(),
            RateLimitOperation::OAuthRevoke.as_str(),
        ],
        [
            "oauth_authorize",
            "oauth_token",
            "oauth_client_registration",
            "oauth_revoke",
        ]
    );
}

#[test]
fn oauth_key_fingerprint_matches_the_provider_contract_vector() -> Result<(), Box<dyn Error>> {
    let context = trusted_context("192.0.2.10", Some("https://client.example/metadata.json"))?;

    assert_eq!(
        RateLimitKey::for_oauth(RateLimitOperation::OAuthAuthorize, &context).fingerprint(),
        &[
            99, 32, 242, 143, 70, 119, 42, 16, 241, 19, 230, 15, 31, 210, 89, 149, 185, 228, 197,
            117, 155, 140, 115, 56, 211, 241, 108, 193, 118, 199, 114, 174,
        ]
    );
    Ok(())
}

#[test]
fn oauth_operation_client_and_ip_inputs_are_isolated() -> Result<(), Box<dyn Error>> {
    let first = trusted_context("192.0.2.10", Some("client-a"))?;
    let other_client = trusted_context("192.0.2.10", Some("client-b"))?;
    let other_ip = trusted_context("192.0.2.11", Some("client-a"))?;
    let operations = [
        RateLimitOperation::OAuthAuthorize,
        RateLimitOperation::OAuthToken,
        RateLimitOperation::OAuthClientRegistration,
        RateLimitOperation::OAuthRevoke,
    ];
    let fingerprints = operations
        .into_iter()
        .map(|operation| *RateLimitKey::for_oauth(operation, &first).fingerprint())
        .chain([
            *RateLimitKey::for_oauth(RateLimitOperation::OAuthAuthorize, &other_client)
                .fingerprint(),
            *RateLimitKey::for_oauth(RateLimitOperation::OAuthAuthorize, &other_ip).fingerprint(),
        ])
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(fingerprints.len(), 6);
    Ok(())
}

#[test]
fn oauth_client_id_is_bounded_and_redacted() -> Result<(), Box<dyn Error>> {
    let client_id = RateLimitClientId::new("https://client.example/metadata.json")?;
    let key = RateLimitKey::for_oauth(
        RateLimitOperation::OAuthToken,
        &TrustedRateLimitContext::new("192.0.2.12".parse()?)
            .with_oauth_client_id(client_id.clone()),
    );

    assert!(RateLimitClientId::new("").is_err());
    assert!(RateLimitClientId::new(&"a".repeat(257)).is_err());
    assert!(RateLimitClientId::new("client secret").is_err());
    assert_eq!(format!("{client_id:?}"), "RateLimitClientId([REDACTED])");
    assert!(!format!("{key:?}").contains("client.example"));
    Ok(())
}
