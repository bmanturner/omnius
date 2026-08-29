//! Trusted identity, operation isolation, spoof resistance, and cardinality contracts.

use std::{error::Error, net::IpAddr, time::Duration};

use axum::{Router, body::Body, http::Request, response::Response, routing::get};
use omnius_core::RequestId;
use omnius_rate_limit_local::{
    LocalRateLimitPolicy, LocalRateLimiter, RateLimitClientId, RateLimitIdentityKind,
    RateLimitOperation, RateLimitToken, TrustedRateLimitContext,
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
    limiter.apply(Router::new().route("/", get(|| async { "ok" })))
}

fn request(context: TrustedRateLimitContext) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::builder().uri("/").body(Body::empty())?;
    request.extensions_mut().insert(context);
    request.extensions_mut().insert(RequestId::new());
    Ok(request)
}

async fn assert_problem(response: Response, code: &str) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        response.headers().get("content-type"),
        Some(&axum::http::HeaderValue::from_static(
            "application/problem+json"
        ))
    );
    let response_request_id = response
        .headers()
        .get("x-request-id")
        .ok_or_else(|| std::io::Error::other("problem response missing request ID"))?
        .to_str()?
        .to_owned();
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    let problem: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(problem["code"], code);
    assert_eq!(problem["request_id"], response_request_id);
    Ok(())
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
    assert_problem(denied, "RATE_LIMITED").await?;

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
    let spoofed_response = app(&limiter).oneshot(spoofed).await?;
    assert_eq!(
        spoofed_response.status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );
    assert_problem(spoofed_response, "RATE_LIMITED").await?;

    let untrusted = Request::builder()
        .uri("/")
        .header("forwarded", "for=203.0.113.4")
        .body(Body::empty())?;
    let untrusted_response = app(&limiter).oneshot(untrusted).await?;
    assert!(untrusted_response.status().is_server_error());
    assert_problem(untrusted_response, "INTERNAL_ERROR").await?;
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

#[tokio::test]
async fn oauth_client_and_ip_discriminators_have_independent_budgets() -> Result<(), Box<dyn Error>>
{
    let limiter = LocalRateLimiter::new(
        RateLimitOperation::OAuthAuthorize,
        RateLimitIdentityKind::OAuthClientIp,
        policy(1_000_000),
    )?;
    let first = TrustedRateLimitContext::new(ip("192.0.2.40")?).with_oauth_client_id(
        RateLimitClientId::new("https://client.example/metadata.json")?,
    );
    let other_client = TrustedRateLimitContext::new(ip("192.0.2.40")?)
        .with_oauth_client_id(RateLimitClientId::new("native-client")?);
    let other_ip = TrustedRateLimitContext::new(ip("192.0.2.41")?).with_oauth_client_id(
        RateLimitClientId::new("https://client.example/metadata.json")?,
    );

    assert!(
        app(&limiter)
            .oneshot(request(first.clone())?)
            .await?
            .status()
            .is_success()
    );
    assert_eq!(
        app(&limiter).oneshot(request(first)?).await?.status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );
    assert!(
        app(&limiter)
            .oneshot(request(other_client)?)
            .await?
            .status()
            .is_success()
    );
    assert!(
        app(&limiter)
            .oneshot(request(other_ip)?)
            .await?
            .status()
            .is_success()
    );
    Ok(())
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
fn oauth_fingerprint_separates_operations_clients_and_ips() -> Result<(), Box<dyn Error>> {
    let first = TrustedRateLimitContext::new(ip("192.0.2.10")?)
        .with_oauth_client_id(RateLimitClientId::new("client-a")?);
    let other_client = TrustedRateLimitContext::new(ip("192.0.2.10")?)
        .with_oauth_client_id(RateLimitClientId::new("client-b")?);
    let other_ip = TrustedRateLimitContext::new(ip("192.0.2.11")?)
        .with_oauth_client_id(RateLimitClientId::new("client-a")?);
    let fingerprints = [
        RateLimitOperation::OAuthAuthorize,
        RateLimitOperation::OAuthToken,
        RateLimitOperation::OAuthClientRegistration,
        RateLimitOperation::OAuthRevoke,
    ]
    .into_iter()
    .map(|operation| first.oauth_key_fingerprint(operation))
    .chain([
        other_client.oauth_key_fingerprint(RateLimitOperation::OAuthAuthorize),
        other_ip.oauth_key_fingerprint(RateLimitOperation::OAuthAuthorize),
    ])
    .collect::<std::collections::HashSet<_>>();

    assert_eq!(fingerprints.len(), 6);
    Ok(())
}

#[test]
fn oauth_key_fingerprint_matches_the_provider_contract_vector() -> Result<(), Box<dyn Error>> {
    let context = TrustedRateLimitContext::new(ip("192.0.2.10")?).with_oauth_client_id(
        RateLimitClientId::new("https://client.example/metadata.json")?,
    );

    assert_eq!(
        context.oauth_key_fingerprint(RateLimitOperation::OAuthAuthorize),
        [
            99, 32, 242, 143, 70, 119, 42, 16, 241, 19, 230, 15, 31, 210, 89, 149, 185, 228, 197,
            117, 155, 140, 115, 56, 211, 241, 108, 193, 118, 199, 114, 174,
        ]
    );
    Ok(())
}

#[test]
fn oauth_client_id_is_bounded_and_redacted() -> Result<(), Box<dyn Error>> {
    let raw_client_id = "https://client.example/metadata.json";
    let client_id = RateLimitClientId::new(raw_client_id)?;
    let context =
        TrustedRateLimitContext::new(ip("192.0.2.10")?).with_oauth_client_id(client_id.clone());

    assert!(RateLimitClientId::new("").is_err());
    assert!(RateLimitClientId::new(&"a".repeat(257)).is_err());
    assert!(RateLimitClientId::new("client secret").is_err());
    assert_eq!(format!("{client_id:?}"), "RateLimitClientId([REDACTED])");
    assert!(!format!("{context:?}").contains(raw_client_id));
    Ok(())
}
