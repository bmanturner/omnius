//! Real bounded JWKS rotation and JWT rejection proofs.

use std::{error::Error, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use rsk_auth_core::{AssuranceLevel, AuthMethod, PrincipalKind, Scope};
use rsk_auth_jwt::{
    BearerPrincipal, JwtAlgorithm, JwtBuildError, JwtConfig, JwtIssuerConfig, JwtVerifier,
    JwtVerifyError,
};
use rsk_config::DeploymentEnvironment;
use rsk_outbound_http::{OutboundHttpClients, OutboundHttpConfig};
use rsk_test_support::{ProviderFake, ProviderMock, ProviderResponse, provider_matchers};
use serde::Serialize;
use time::OffsetDateTime;
use tower::ServiceExt as _;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "rsk-api";
const SUBJECT: &str = "01890f2a-0000-7000-8000-000000000001";
const TENANT: &str = "01890f2a-0000-7000-8000-000000000002";
const KEY_ONE: &[u8] = include_bytes!("test_rsa_key.pem");
const KEY_TWO: &[u8] = include_bytes!("test_rsa_key_rotated.pem");

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone, Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    exp: u64,
    nbf: u64,
    iat: u64,
    kind: PrincipalKind,
    tenant_id: Option<String>,
    scope: Option<String>,
    assurance: Option<AssuranceLevel>,
}
async fn protected(BearerPrincipal(principal): BearerPrincipal) -> StatusCode {
    if principal.auth_method == AuthMethod::Jwt {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

fn now() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default()
}

fn claims() -> Claims {
    let now = now();
    Claims {
        sub: SUBJECT.to_owned(),
        iss: ISSUER.to_owned(),
        aud: vec![AUDIENCE.to_owned()],
        exp: now + 300,
        nbf: now.saturating_sub(5),
        iat: now.saturating_sub(5),
        kind: PrincipalKind::User,
        tenant_id: Some(TENANT.to_owned()),
        scope: Some("write:records read:records write:records".to_owned()),
        assurance: Some(AssuranceLevel::Aal2),
    }
}

fn signing_key(pem: &[u8]) -> Result<EncodingKey, jsonwebtoken::errors::Error> {
    EncodingKey::from_rsa_pem(pem)
}

fn jwk(pem: &[u8], kid: &str) -> Result<Jwk, jsonwebtoken::errors::Error> {
    let mut jwk = Jwk::from_encoding_key(&signing_key(pem)?, Algorithm::RS256)?;
    jwk.common.key_id = Some(kid.to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
    Ok(jwk)
}

fn jwks_body(keys: Vec<Jwk>) -> Result<String, serde_json::Error> {
    serde_json::to_string(&JwkSet { keys })
}

fn token(
    pem: &[u8],
    kid: Option<&str>,
    token_type: Option<&str>,
    claims: &Claims,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    header.typ = token_type.map(str::to_owned);
    encode(&header, claims, &signing_key(pem)?)
}

fn config(fake: &ProviderFake) -> Result<JwtConfig, Box<dyn Error>> {
    Ok(JwtConfig {
        enabled: true,
        issuers: vec![JwtIssuerConfig {
            issuer: ISSUER.to_owned(),
            jwks_url: fake.endpoint("/jwks")?.to_string(),
        }],
        audiences: vec![AUDIENCE.to_owned()],
        algorithms: vec![JwtAlgorithm::RS256],
        token_types: vec!["at+jwt".to_owned()],
        min_refresh_interval: Duration::from_secs(30),
        ..JwtConfig::default()
    })
}

fn clients() -> Result<OutboundHttpClients, Box<dyn Error>> {
    Ok(OutboundHttpClients::new(&OutboundHttpConfig::default())?)
}

async fn mount_jwks(
    fake: &ProviderFake,
    body: String,
    expected: u64,
) -> rsk_test_support::ProviderMockGuard {
    fake.mount_scoped(
        ProviderMock::given(provider_matchers::method("GET"))
            .and(provider_matchers::path("/jwks"))
            .respond_with(ProviderResponse::new(200).set_body_raw(body, "application/json"))
            .expect(expected),
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "one table-like security flow keeps every JWT rejection class beside the valid control"
)]
#[tokio::test]
async fn verifies_claim_policy_and_maps_canonical_principal() -> TestResult {
    let fake = ProviderFake::start().await?;
    let initial = mount_jwks(&fake, jwks_body(vec![jwk(KEY_ONE, "key-1")?])?, 1).await;
    let verifier =
        JwtVerifier::initialize(&config(&fake)?, DeploymentEnvironment::Test, clients()?).await?;
    drop(initial);

    let valid = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &claims())?;
    let principal = verifier.verify(&valid).await?;
    assert_eq!(principal.auth_method, AuthMethod::Jwt);
    assert_eq!(principal.kind, PrincipalKind::User);
    assert_eq!(principal.assurance, AssuranceLevel::Aal2);
    assert_eq!(principal.subject_id.to_string(), SUBJECT);
    assert_eq!(
        principal.tenant_id.ok_or("missing tenant")?.to_string(),
        TENANT
    );
    assert_eq!(
        principal
            .scopes
            .iter()
            .map(Scope::as_str)
            .collect::<Vec<_>>(),
        ["read:records", "write:records"]
    );

    let app = Router::new()
        .route("/protected", get(protected))
        .with_state(verifier.clone());
    let authorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {valid}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(authorized.status(), StatusCode::OK);
    let missing = app
        .oneshot(Request::builder().uri("/protected").body(Body::empty())?)
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.headers().get(header::WWW_AUTHENTICATE),
        Some(&"Bearer".parse::<axum::http::HeaderValue>()?)
    );

    let mut symmetric_header = Header::new(Algorithm::HS256);
    symmetric_header.kid = Some("key-1".to_owned());
    symmetric_header.typ = Some("at+jwt".to_owned());
    let symmetric = encode(
        &symmetric_header,
        &claims(),
        &EncodingKey::from_secret(b"not-a-public-key"),
    )?;
    assert_eq!(
        verifier.verify(&symmetric).await,
        Err(JwtVerifyError::AlgorithmRejected)
    );

    let missing_kid = token(KEY_ONE, None, Some("at+jwt"), &claims())?;
    assert_eq!(
        verifier.verify(&missing_kid).await,
        Err(JwtVerifyError::KeyIdRejected)
    );
    let mut required_header = Header::new(Algorithm::RS256);
    required_header.kid = Some("key-1".to_owned());
    required_header.typ = Some("at+jwt".to_owned());
    let current = now();
    let missing_nbf = encode(
        &required_header,
        &serde_json::json!({
            "sub": SUBJECT,
            "iss": ISSUER,
            "aud": [AUDIENCE],
            "exp": current + 300,
            "iat": current,
            "kind": "user"
        }),
        &signing_key(KEY_ONE)?,
    )?;
    assert!(verifier.verify(&missing_nbf).await.is_err());
    let wrong_class = token(KEY_ONE, Some("key-1"), Some("JWT"), &claims())?;
    assert_eq!(
        verifier.verify(&wrong_class).await,
        Err(JwtVerifyError::TokenClassRejected)
    );

    let mut wrong_issuer = claims();
    wrong_issuer.iss = "https://other.example.test".to_owned();
    let wrong_issuer = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &wrong_issuer)?;
    assert!(verifier.verify(&wrong_issuer).await.is_err());
    let mut wrong_audience = claims();
    wrong_audience.aud = vec!["other-api".to_owned()];
    let wrong_audience = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &wrong_audience)?;
    assert!(verifier.verify(&wrong_audience).await.is_err());
    let mut expired = claims();
    expired.exp = now().saturating_sub(60);
    expired.iat = expired.exp.saturating_sub(60);
    expired.nbf = expired.iat;
    let expired = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &expired)?;
    assert!(verifier.verify(&expired).await.is_err());
    let mut future = claims();
    future.nbf = now() + 120;
    future.exp = future.nbf + 300;
    let future = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &future)?;
    assert!(verifier.verify(&future).await.is_err());
    let wrong_key = token(KEY_TWO, Some("key-1"), Some("at+jwt"), &claims())?;
    assert!(verifier.verify(&wrong_key).await.is_err());
    let mut long_lived = claims();
    long_lived.exp = long_lived.iat + 3_601;
    let long_lived = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &long_lived)?;
    assert!(verifier.verify(&long_lived).await.is_err());
    assert_eq!(
        verifier.verify(&"x".repeat(16 * 1_024 + 1)).await,
        Err(JwtVerifyError::MalformedToken)
    );
    assert!(!format!("{:?}", verifier.verify(&valid).await).contains(&valid));
    assert_eq!(fake.requests().await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn unknown_kid_refresh_is_coalesced_and_rotates_keys() -> TestResult {
    let fake = ProviderFake::start().await?;
    let initial = mount_jwks(&fake, jwks_body(vec![jwk(KEY_ONE, "key-1")?])?, 1).await;
    let verifier =
        JwtVerifier::initialize(&config(&fake)?, DeploymentEnvironment::Test, clients()?).await?;
    drop(initial);

    let rotated = mount_jwks(&fake, jwks_body(vec![jwk(KEY_TWO, "key-2")?])?, 1).await;
    let rotated_token = token(KEY_TWO, Some("key-2"), Some("at+jwt"), &claims())?;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let verifier = verifier.clone();
        let token = rotated_token.clone();
        tasks.push(tokio::spawn(async move { verifier.verify(&token).await }));
    }
    for task in tasks {
        assert_eq!(task.await??.auth_method, AuthMethod::Jwt);
    }
    drop(rotated);
    assert_eq!(fake.requests().await?.len(), 2);

    let old_token = token(KEY_ONE, Some("key-1"), Some("at+jwt"), &claims())?;
    assert!(verifier.verify(&old_token).await.is_err());
    assert_eq!(fake.requests().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn colliding_kids_refresh_only_the_issuer_with_an_unknown_key() -> TestResult {
    let issuer_a = ProviderFake::start().await?;
    let issuer_b = ProviderFake::start().await?;
    let initial_a = mount_jwks(&issuer_a, jwks_body(vec![jwk(KEY_ONE, "key-1")?])?, 1).await;
    let initial_b = mount_jwks(&issuer_b, jwks_body(vec![jwk(KEY_ONE, "old")?])?, 1).await;
    let mut verifier_config = config(&issuer_a)?;
    verifier_config.issuers.push(JwtIssuerConfig {
        issuer: "https://issuer-b.example.test".to_owned(),
        jwks_url: issuer_b.endpoint("/jwks")?.to_string(),
    });
    let verifier =
        JwtVerifier::initialize(&verifier_config, DeploymentEnvironment::Test, clients()?).await?;
    drop((initial_a, initial_b));

    let rotated_b = mount_jwks(&issuer_b, jwks_body(vec![jwk(KEY_TWO, "key-1")?])?, 1).await;
    let mut issuer_b_claims = claims();
    issuer_b_claims.iss = "https://issuer-b.example.test".to_owned();
    let issuer_b_token = token(KEY_TWO, Some("key-1"), Some("at+jwt"), &issuer_b_claims)?;
    assert_eq!(
        verifier
            .verify(&issuer_b_token)
            .await?
            .subject_id
            .to_string(),
        SUBJECT
    );
    drop(rotated_b);
    assert_eq!(issuer_a.requests().await?.len(), 1);
    assert_eq!(issuer_b.requests().await?.len(), 2);
    Ok(())
}
#[tokio::test]
async fn rejects_duplicate_keys_and_oversize_jwks() -> TestResult {
    let duplicate_fake = ProviderFake::start().await?;

    duplicate_fake
        .mount(
            ProviderMock::given(provider_matchers::path("/jwks")).respond_with(
                ProviderResponse::new(200).set_body_raw(
                    jwks_body(vec![jwk(KEY_ONE, "same")?, jwk(KEY_TWO, "same")?])?,
                    "application/json",
                ),
            ),
        )
        .await;
    let duplicate = JwtVerifier::initialize(
        &config(&duplicate_fake)?,
        DeploymentEnvironment::Test,
        clients()?,
    )
    .await;
    assert!(matches!(duplicate, Err(JwtBuildError::InitialJwks)));

    let oversize_fake = ProviderFake::start().await?;
    oversize_fake
        .mount(
            ProviderMock::given(provider_matchers::path("/jwks")).respond_with(
                ProviderResponse::new(200).set_body_raw(
                    format!(r#"{{"keys":[],"padding":"{}"}}"#, "x".repeat(2_048)),
                    "application/json",
                ),
            ),
        )
        .await;
    let mut oversize_config = config(&oversize_fake)?;
    oversize_config.max_jwks_bytes = 1_024;
    let oversize =
        JwtVerifier::initialize(&oversize_config, DeploymentEnvironment::Test, clients()?).await;
    assert!(matches!(oversize, Err(JwtBuildError::InitialJwks)));

    let unavailable_fake = ProviderFake::start().await?;
    unavailable_fake
        .mount(
            ProviderMock::given(provider_matchers::path("/jwks"))
                .respond_with(ProviderResponse::new(503)),
        )
        .await;
    let unavailable = JwtVerifier::initialize(
        &config(&unavailable_fake)?,
        DeploymentEnvironment::Test,
        clients()?,
    )
    .await;
    assert!(matches!(unavailable, Err(JwtBuildError::InitialJwks)));
    Ok(())
}
