//! Trusted identity, operation isolation, spoof resistance, and cardinality contracts.

use std::{error::Error, net::IpAddr, time::Duration};

use axum::{Router, body::Body, http::Request, routing::get};
use rsk_rate_limit_local::{
    LocalRateLimitPolicy, LocalRateLimiter, RateLimitIdentityKind, RateLimitOperation,
    RateLimitToken, TrustedRateLimitContext,
};
use tower::ServiceExt;

fn policy(identity_buckets: u32) -> LocalRateLimitPolicy {
    LocalRateLimitPolicy {
        replenish_every: Duration::from_secs(60),
        burst_size: 1,
        identity_buckets,
    }
}

fn ip(value: &str) -> Result<IpAddr, Box<dyn Error>> {
    Ok(value.parse()?)
}

fn app(limiter: &LocalRateLimiter) -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(limiter.layer())
}

fn request(context: TrustedRateLimitContext) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::builder().uri("/").body(Body::empty())?;
    request.extensions_mut().insert(context);
    Ok(request)
}

#[tokio::test]
async fn operation_and_account_identity_have_independent_budgets() -> Result<(), Box<dyn Error>> {
    let login = LocalRateLimiter::new(
        RateLimitOperation::Login,
        RateLimitIdentityKind::Account,
        policy(1024),
    )?;
    let recovery = LocalRateLimiter::new(
        RateLimitOperation::Recovery,
        RateLimitIdentityKind::Account,
        policy(1024),
    )?;
    let account_a = TrustedRateLimitContext::new(ip("192.0.2.1")?)
        .with_account(RateLimitToken::new("account-a")?);
    let account_b = TrustedRateLimitContext::new(ip("192.0.2.1")?)
        .with_account(RateLimitToken::new("account-b")?);

    assert!(
        app(&login)
            .oneshot(request(account_a.clone())?)
            .await?
            .status()
            .is_success()
    );
    let denied = app(&login).oneshot(request(account_a.clone())?).await?;
    assert_eq!(denied.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert!(denied.headers().contains_key("retry-after"));
    assert!(denied.headers().contains_key("x-ratelimit-limit"));

    assert!(
        app(&login)
            .oneshot(request(account_b)?)
            .await?
            .status()
            .is_success()
    );
    assert!(
        app(&recovery)
            .oneshot(request(account_a)?)
            .await?
            .status()
            .is_success()
    );
    Ok(())
}

#[tokio::test]
async fn forwarding_headers_cannot_spoof_the_trusted_ip_key() -> Result<(), Box<dyn Error>> {
    let limiter = LocalRateLimiter::new(
        RateLimitOperation::Login,
        RateLimitIdentityKind::Ip,
        policy(1024),
    )?;
    let context = TrustedRateLimitContext::new(ip("192.0.2.10")?);
    assert!(
        app(&limiter)
            .oneshot(request(context.clone())?)
            .await?
            .status()
            .is_success()
    );

    let mut spoofed = request(context)?;
    spoofed.headers_mut().insert(
        "x-forwarded-for",
        axum::http::HeaderValue::from_static("203.0.113.99"),
    );
    assert_eq!(
        app(&limiter).oneshot(spoofed).await?.status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );

    let untrusted = Request::builder()
        .uri("/")
        .header("forwarded", "for=203.0.113.4")
        .body(Body::empty())?;
    assert!(
        app(&limiter)
            .oneshot(untrusted)
            .await?
            .status()
            .is_server_error()
    );
    Ok(())
}

#[tokio::test]
async fn adversarial_identity_cardinality_is_hard_bounded() -> Result<(), Box<dyn Error>> {
    let limiter = LocalRateLimiter::new(
        RateLimitOperation::Search,
        RateLimitIdentityKind::Account,
        policy(2),
    )?;
    for index in 0..1000 {
        let context = TrustedRateLimitContext::new(ip("192.0.2.20")?)
            .with_account(RateLimitToken::new(format!("account-{index}"))?);
        let _response = app(&limiter).oneshot(request(context)?).await?;
    }
    assert!(limiter.len() <= usize::try_from(limiter.identity_buckets())?);
    limiter.retain_recent();
    assert!(limiter.len() <= 2);
    Ok(())
}

#[test]
fn policy_and_token_bounds_are_rejected() {
    assert!(RateLimitToken::new("").is_err());
    assert!(RateLimitToken::new("a".repeat(129)).is_err());
    assert!(RateLimitToken::new("contains space").is_err());
    assert!(
        LocalRateLimitPolicy {
            replenish_every: Duration::ZERO,
            burst_size: 1,
            identity_buckets: 1,
        }
        .quota()
        .is_err()
    );
    assert!(
        LocalRateLimitPolicy {
            replenish_every: Duration::from_secs(1),
            burst_size: 0,
            identity_buckets: 1,
        }
        .quota()
        .is_err()
    );
    assert!(
        LocalRateLimitPolicy {
            replenish_every: Duration::from_secs(1),
            burst_size: 1,
            identity_buckets: 0,
        }
        .quota()
        .is_err()
    );
}
