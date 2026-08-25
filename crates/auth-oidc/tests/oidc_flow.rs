//! End-to-end authorization-code protocol proofs against a real provider fake.

use std::{collections::HashMap, error::Error, str, time::Duration};

use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use rsk_auth_oidc::{
    CompletedAuthorization, FlowPurpose, OidcConfig, OidcFlow, OidcFlowError, OidcPendingStore,
    OidcPendingStoreError, OidcProviderConfig, PendingAuthorizationId,
};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_outbound_http::{OutboundHttpClients, OutboundHttpConfig, Url};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{
    PostgresFixture, ProviderFake, ProviderMock, ProviderResponse, provider_matchers,
};
use serde::Serialize;
use time::OffsetDateTime;

const PROVIDER_ID: &str = "example";
const CLIENT_ID: &str = "oidc-client";
const CLIENT_SECRET: &str = "test-client-secret";
const REDIRECT_URI: &str = "http://client.example.test/oidc/callback";
const AUTHORIZATION_CODE: &str = "one-time-authorization-code";
const ACCESS_TOKEN: &str = "opaque-access-token";
const SUBJECT: &str = "provider-user-123";
const KEY_ID: &str = "oidc-key-1";
const ROTATED_KEY_ID: &str = "oidc-key-2";
const KEY: &[u8] = include_bytes!("../../auth-jwt/tests/test_rsa_key.pem");
const ROTATED_KEY: &[u8] = include_bytes!("../../auth-jwt/tests/test_rsa_key_rotated.pem");
const FIRST_MIGRATION: i64 = 2_026_082_301;
const MIGRATION_HEAD: i64 = 2_026_082_313;

type TestResult = Result<(), Box<dyn Error>>;

struct TestAuthorizationStart {
    authorization_url: Url,
    pending_id: PendingAuthorizationId,
}

impl TestAuthorizationStart {
    fn into_parts(self) -> (Url, PendingAuthorizationId) {
        (self.authorization_url, self.pending_id)
    }
}

struct TestFlow {
    flow: OidcFlow,
    pending_store: OidcPendingStore,
    _fixture: PostgresFixture,
}

impl TestFlow {
    async fn new(flow: OidcFlow) -> Result<Self, Box<dyn Error>> {
        let fixture = PostgresFixture::start().await?;
        let pool = PostgresPool::connect(
            &postgres_config(fixture.database_url().clone()),
            DeploymentEnvironment::Test,
        )
        .await?;
        MigrationRunner::new(
            pool.clone(),
            &MIGRATOR,
            SchemaVersionRange::new(FIRST_MIGRATION, MIGRATION_HEAD)?,
            migration_config(),
            DeploymentEnvironment::Test,
        )?
        .run()
        .await?;
        Ok(Self {
            flow,
            pending_store: OidcPendingStore::new(pool),
            _fixture: fixture,
        })
    }

    async fn start_login(
        &self,
        provider_id: &str,
    ) -> Result<TestAuthorizationStart, OidcFlowError> {
        let issued = self
            .pending_store
            .issue(self.flow.start_login(provider_id)?)
            .await
            .map_err(|_| OidcFlowError::InternalState)?;
        let (authorization_url, pending_id) = issued.into_parts();
        Ok(TestAuthorizationStart {
            authorization_url,
            pending_id,
        })
    }

    async fn start_link(
        &self,
        provider_id: &str,
        principal: &Principal,
    ) -> Result<TestAuthorizationStart, OidcFlowError> {
        let issued = self
            .pending_store
            .issue(self.flow.start_link(provider_id, principal)?)
            .await
            .map_err(|_| OidcFlowError::InternalState)?;
        let (authorization_url, pending_id) = issued.into_parts();
        Ok(TestAuthorizationStart {
            authorization_url,
            pending_id,
        })
    }

    async fn complete(
        &self,
        pending_id: PendingAuthorizationId,
        provider_id: &str,
        redirect_uri: &str,
        authorization_code: &str,
        state: &str,
    ) -> Result<CompletedAuthorization, OidcFlowError> {
        let pending = self
            .pending_store
            .take(pending_id)
            .await
            .map_err(|_| OidcFlowError::InternalState)?;
        self.flow
            .complete(
                pending,
                provider_id,
                redirect_uri,
                authorization_code,
                state,
            )
            .await
    }
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-auth-oidc-flow-test".to_owned(),
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

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<&'a str>,
}

struct AuthorizationParams {
    state: String,
    nonce: String,
    code_challenge: String,
}

fn clients() -> Result<OutboundHttpClients, Box<dyn Error>> {
    Ok(OutboundHttpClients::new(&OutboundHttpConfig::default())?)
}

fn config(fake: &ProviderFake) -> OidcConfig {
    OidcConfig {
        enabled: true,
        providers: vec![OidcProviderConfig {
            provider_id: PROVIDER_ID.to_owned(),
            issuer: fake.base_url().to_string(),
            client_id: CLIENT_ID.to_owned(),
            client_secret: SecretString::from(CLIENT_SECRET.to_owned()),
            redirect_uri: REDIRECT_URI.to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        }],
        ..OidcConfig::default()
    }
}

fn discovery_body(fake: &ProviderFake) -> Result<String, Box<dyn Error>> {
    Ok(serde_json::to_string(&serde_json::json!({
        "issuer": fake.base_url().as_str(),
        "authorization_endpoint": fake.endpoint("/authorize")?.as_str(),
        "token_endpoint": fake.endpoint("/token")?.as_str(),
        "jwks_uri": fake.endpoint("/jwks")?.as_str(),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    }))?)
}

async fn mount_discovery(fake: &ProviderFake, expected: u64) -> Result<(), Box<dyn Error>> {
    fake.mount(
        ProviderMock::given(provider_matchers::method("GET"))
            .and(provider_matchers::path("/.well-known/openid-configuration"))
            .respond_with(
                ProviderResponse::new(200).set_body_raw(discovery_body(fake)?, "application/json"),
            )
            .expect(expected),
    )
    .await;
    Ok(())
}

fn jwk(pem: &[u8], kid: &str) -> Result<Jwk, jsonwebtoken::errors::Error> {
    let key = EncodingKey::from_rsa_pem(pem)?;
    let mut jwk = Jwk::from_encoding_key(&key, Algorithm::RS256)?;
    jwk.common.key_id = Some(kid.to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
    Ok(jwk)
}

fn jwks_body(pem: &[u8], kid: &str) -> Result<String, Box<dyn Error>> {
    Ok(serde_json::to_string(&JwkSet {
        keys: vec![jwk(pem, kid)?],
    })?)
}

async fn mount_jwks(
    fake: &ProviderFake,
    pem: &[u8],
    kid: &str,
    expected: u64,
) -> Result<rsk_test_support::ProviderMockGuard, Box<dyn Error>> {
    Ok(fake
        .mount_scoped(
            ProviderMock::given(provider_matchers::method("GET"))
                .and(provider_matchers::path("/jwks"))
                .respond_with(
                    ProviderResponse::new(200)
                        .set_body_raw(jwks_body(pem, kid)?, "application/json"),
                )
                .expect(expected),
        )
        .await)
}

async fn initialize(fake: &ProviderFake) -> Result<TestFlow, Box<dyn Error>> {
    mount_discovery(fake, 1).await?;
    let jwks = mount_jwks(fake, KEY, KEY_ID, 1).await?;
    let flow = OidcFlow::initialize(&config(fake), DeploymentEnvironment::Test, clients()?).await?;
    drop(jwks);
    TestFlow::new(flow).await
}

fn authorization_params(url: &Url) -> Result<AuthorizationParams, Box<dyn Error>> {
    let query = url
        .query_pairs()
        .into_owned()
        .collect::<HashMap<String, String>>();
    assert!(
        query
            .get("response_type")
            .is_some_and(|value| value == "code")
    );
    assert!(
        query
            .get("client_id")
            .is_some_and(|value| value == CLIENT_ID)
    );
    assert!(
        query
            .get("redirect_uri")
            .is_some_and(|value| value == REDIRECT_URI)
    );
    assert!(
        query
            .get("code_challenge_method")
            .is_some_and(|value| value == "S256")
    );
    let scope = query
        .get("scope")
        .ok_or("authorization URL omitted scope")?;
    assert!(scope.split(' ').any(|value| value == "openid"));
    assert!(scope.split(' ').any(|value| value == "profile"));
    Ok(AuthorizationParams {
        state: query
            .get("state")
            .filter(|value| !value.is_empty())
            .ok_or("authorization URL omitted state")?
            .to_owned(),
        nonce: query
            .get("nonce")
            .filter(|value| !value.is_empty())
            .ok_or("authorization URL omitted nonce")?
            .to_owned(),
        code_challenge: query
            .get("code_challenge")
            .filter(|value| !value.is_empty())
            .ok_or("authorization URL omitted PKCE challenge")?
            .to_owned(),
    })
}

fn signed_id_token(
    pem: &[u8],
    kid: &str,
    issuer: &str,
    audience: &str,
    nonce: &str,
) -> Result<String, Box<dyn Error>> {
    signed_id_token_with_at_hash(pem, kid, issuer, audience, nonce, None)
}

fn signed_id_token_with_at_hash(
    pem: &[u8],
    kid: &str,
    issuer: &str,
    audience: &str,
    nonce: &str,
    at_hash: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = IdTokenClaims {
        iss: issuer,
        sub: SUBJECT,
        aud: audience,
        exp: now + 300,
        iat: now,
        nonce,
        at_hash,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    let token = encode(&header, &claims, &EncodingKey::from_rsa_pem(pem)?)?;
    assert!(!token.is_empty());
    Ok(token)
}

async fn mount_token_response(
    fake: &ProviderFake,
    id_token: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let mut body = serde_json::json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 300
    });
    if let Some(id_token) = id_token {
        body["id_token"] = serde_json::Value::String(id_token.to_owned());
    }
    fake.mount(
        ProviderMock::given(provider_matchers::method("POST"))
            .and(provider_matchers::path("/token"))
            .respond_with(
                ProviderResponse::new(200)
                    .set_body_raw(serde_json::to_string(&body)?, "application/json"),
            )
            .expect(1),
    )
    .await;
    Ok(())
}

fn assert_flow_error<T>(
    result: Result<T, OidcFlowError>,
    expected: OidcFlowError,
    sensitive_values: &[&str],
) {
    let Some(error) = result.err() else {
        panic!("OIDC flow unexpectedly succeeded");
    };
    assert_eq!(error, expected);
    let rendered = format!("{error:?} {error}");
    assert!(
        sensitive_values
            .iter()
            .all(|value| value.is_empty() || !rendered.contains(value)),
        "OIDC error exposed a sensitive value"
    );
}

fn token_requests(
    requests: &[rsk_test_support::ProviderRequest],
) -> impl Iterator<Item = &rsk_test_support::ProviderRequest> {
    requests
        .iter()
        .filter(|request| request.url.path() == "/token")
}

#[tokio::test]
async fn successful_flow_verifies_identity_and_binds_pkce_verifier_to_start_url() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let (authorization_url, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let authorization = authorization_params(&authorization_url)?;
    let id_token = signed_id_token(
        KEY,
        KEY_ID,
        fake.base_url().as_str(),
        CLIENT_ID,
        &authorization.nonce,
    )?;
    mount_token_response(&fake, Some(&id_token)).await?;

    let completed = flow
        .complete(
            pending,
            PROVIDER_ID,
            REDIRECT_URI,
            AUTHORIZATION_CODE,
            &authorization.state,
        )
        .await?;

    assert_eq!(completed.purpose(), &FlowPurpose::Login);
    assert_eq!(completed.identity().provider(), fake.base_url().as_str());
    assert_eq!(completed.identity().provider_subject(), SUBJECT);
    let requests = fake.requests().await?;
    let mut token_requests = token_requests(&requests);
    let request = token_requests
        .next()
        .ok_or("token endpoint was not called")?;
    assert!(token_requests.next().is_none());
    let body = str::from_utf8(&request.body)?;
    let form = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();
    assert!(
        form.get("grant_type")
            .is_some_and(|value| value == "authorization_code")
    );
    assert!(
        form.get("code")
            .is_some_and(|value| value == AUTHORIZATION_CODE)
    );
    assert!(
        form.get("redirect_uri")
            .is_some_and(|value| value == REDIRECT_URI)
    );
    let verifier = form
        .get("code_verifier")
        .filter(|value| !value.is_empty())
        .ok_or("token request omitted PKCE verifier")?;
    let computed =
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.to_owned()));
    assert!(
        computed.as_str() == authorization.code_challenge,
        "token PKCE verifier did not match the authorization challenge"
    );
    Ok(())
}

#[tokio::test]
async fn rejects_issuer_audience_and_nonce_claim_mismatches() -> TestResult {
    for (issuer, audience, nonce) in [
        ("http://other-issuer.example/", CLIENT_ID, None),
        ("", "another-client", None),
        ("", CLIENT_ID, Some("wrong-nonce")),
    ] {
        let fake = ProviderFake::start().await?;
        let flow = initialize(&fake).await?;
        let (authorization_url, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
        let authorization = authorization_params(&authorization_url)?;
        let issuer = if issuer.is_empty() {
            fake.base_url().as_str()
        } else {
            issuer
        };
        let nonce = nonce.unwrap_or(&authorization.nonce);
        let id_token = signed_id_token(KEY, KEY_ID, issuer, audience, nonce)?;
        mount_token_response(&fake, Some(&id_token)).await?;

        let result = flow
            .complete(
                pending,
                PROVIDER_ID,
                REDIRECT_URI,
                AUTHORIZATION_CODE,
                &authorization.state,
            )
            .await;
        assert_flow_error(
            result,
            OidcFlowError::IdTokenRejected,
            &[issuer, audience, nonce, AUTHORIZATION_CODE, ACCESS_TOKEN],
        );
    }
    Ok(())
}

#[tokio::test]
async fn state_mismatch_is_rejected_before_any_token_request() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let (_, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let replay_id: PendingAuthorizationId =
        serde_json::from_value(serde_json::to_value(&pending)?)?;
    let attacker_state = "attacker-controlled-state";

    let result = flow
        .complete(
            pending,
            PROVIDER_ID,
            REDIRECT_URI,
            AUTHORIZATION_CODE,
            attacker_state,
        )
        .await;
    assert_flow_error(
        result,
        OidcFlowError::StateMismatch,
        &[attacker_state, AUTHORIZATION_CODE, CLIENT_SECRET],
    );
    assert!(matches!(
        flow.pending_store.take(replay_id).await,
        Err(OidcPendingStoreError::UnavailableAuthorization)
    ));
    assert_eq!(token_requests(&fake.requests().await?).count(), 0);
    Ok(())
}

#[tokio::test]
async fn concurrent_callback_takes_have_exactly_one_winner() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let (_, pending_id) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let replay_id: PendingAuthorizationId =
        serde_json::from_value(serde_json::to_value(&pending_id)?)?;
    let competing_store = flow.pending_store.clone();

    let (first, second) = tokio::join!(
        flow.pending_store.take(pending_id),
        competing_store.take(replay_id)
    );
    let successes = usize::from(first.is_ok()) + usize::from(second.is_ok());
    let consumed = usize::from(matches!(
        first,
        Err(OidcPendingStoreError::UnavailableAuthorization)
    )) + usize::from(matches!(
        second,
        Err(OidcPendingStoreError::UnavailableAuthorization)
    ));
    assert_eq!((successes, consumed), (1, 1));
    Ok(())
}

#[tokio::test]
async fn redirect_uri_must_match_exactly_before_any_token_request() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let (authorization_url, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let authorization = authorization_params(&authorization_url)?;
    let mismatched_redirect = "http://client.example.test/oidc/callback/";

    let result = flow
        .complete(
            pending,
            PROVIDER_ID,
            mismatched_redirect,
            AUTHORIZATION_CODE,
            &authorization.state,
        )
        .await;
    assert_flow_error(
        result,
        OidcFlowError::ContextMismatch,
        &[
            mismatched_redirect,
            AUTHORIZATION_CODE,
            &authorization.state,
        ],
    );
    assert_eq!(token_requests(&fake.requests().await?).count(), 0);
    Ok(())
}

#[tokio::test]
async fn token_response_without_id_token_is_rejected() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let (authorization_url, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let authorization = authorization_params(&authorization_url)?;
    mount_token_response(&fake, None).await?;

    let result = flow
        .complete(
            pending,
            PROVIDER_ID,
            REDIRECT_URI,
            AUTHORIZATION_CODE,
            &authorization.state,
        )
        .await;
    assert_flow_error(
        result,
        OidcFlowError::MissingIdToken,
        &[AUTHORIZATION_CODE, ACCESS_TOKEN, CLIENT_SECRET],
    );
    Ok(())
}

#[tokio::test]
async fn access_token_hash_mismatch_is_rejected() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let (authorization_url, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let authorization = authorization_params(&authorization_url)?;
    let invalid_hash = "invalid-access-token-hash";
    let id_token = signed_id_token_with_at_hash(
        KEY,
        KEY_ID,
        fake.base_url().as_str(),
        CLIENT_ID,
        &authorization.nonce,
        Some(invalid_hash),
    )?;
    mount_token_response(&fake, Some(&id_token)).await?;

    let result = flow
        .complete(
            pending,
            PROVIDER_ID,
            REDIRECT_URI,
            AUTHORIZATION_CODE,
            &authorization.state,
        )
        .await;
    assert_flow_error(
        result,
        OidcFlowError::IdTokenRejected,
        &[
            invalid_hash,
            ACCESS_TOKEN,
            AUTHORIZATION_CODE,
            CLIENT_SECRET,
        ],
    );
    Ok(())
}

fn user_principal(
    subject_id: SubjectId,
    authenticated_at: OffsetDateTime,
) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        subject_id,
        PrincipalKind::User,
        None,
        AuthMethod::Session,
        authenticated_at,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

#[tokio::test]
async fn account_link_requires_recent_user_authentication() -> TestResult {
    let fake = ProviderFake::start().await?;
    let flow = initialize(&fake).await?;
    let subject_id: SubjectId = "01890f2a-0000-7000-8000-000000000001".parse()?;
    let old = user_principal(
        subject_id,
        OffsetDateTime::now_utc() - time::Duration::minutes(6),
    )?;
    assert_flow_error(
        flow.start_link(PROVIDER_ID, &old).await,
        OidcFlowError::LinkProofRequired,
        &[&subject_id.to_string()],
    );

    let recent = user_principal(subject_id, OffsetDateTime::now_utc())?;
    let (_, pending_id) = flow.start_link(PROVIDER_ID, &recent).await?.into_parts();
    let rendered = format!("{pending_id:?}");
    assert!(!rendered.contains(&subject_id.to_string()));
    Ok(())
}

#[tokio::test]
async fn callback_cannot_outlive_the_initiating_link_proof() -> TestResult {
    let fake = ProviderFake::start().await?;
    mount_discovery(&fake, 1).await?;
    let jwks = mount_jwks(&fake, KEY, KEY_ID, 1).await?;
    let mut oidc_config = config(&fake);
    oidc_config.link_proof_max_age = std::time::Duration::from_secs(30);
    let raw_flow =
        OidcFlow::initialize(&oidc_config, DeploymentEnvironment::Test, clients()?).await?;
    drop(jwks);
    let flow = TestFlow::new(raw_flow).await?;

    let subject_id: SubjectId = "01890f2a-0000-7000-8000-000000000002".parse()?;
    let at_deadline = user_principal(
        subject_id,
        OffsetDateTime::now_utc() - time::Duration::seconds(30),
    )?;
    let (authorization_url, pending) = flow
        .start_link(PROVIDER_ID, &at_deadline)
        .await?
        .into_parts();
    let authorization = authorization_params(&authorization_url)?;
    let result = flow
        .complete(
            pending,
            PROVIDER_ID,
            REDIRECT_URI,
            AUTHORIZATION_CODE,
            &authorization.state,
        )
        .await;

    assert_flow_error(
        result,
        OidcFlowError::LinkProofRequired,
        &[AUTHORIZATION_CODE, &subject_id.to_string()],
    );
    assert_eq!(token_requests(&fake.requests().await?).count(), 0);
    Ok(())
}

#[tokio::test]
async fn unknown_signing_key_triggers_one_rediscovery_and_then_succeeds() -> TestResult {
    let fake = ProviderFake::start().await?;
    mount_discovery(&fake, 2).await?;
    let initial_jwks = mount_jwks(&fake, KEY, KEY_ID, 1).await?;
    let raw_flow =
        OidcFlow::initialize(&config(&fake), DeploymentEnvironment::Test, clients()?).await?;
    drop(initial_jwks);
    let flow = TestFlow::new(raw_flow).await?;
    let rotated_jwks = mount_jwks(&fake, ROTATED_KEY, ROTATED_KEY_ID, 1).await?;
    let (authorization_url, pending) = flow.start_login(PROVIDER_ID).await?.into_parts();
    let authorization = authorization_params(&authorization_url)?;
    let id_token = signed_id_token(
        ROTATED_KEY,
        ROTATED_KEY_ID,
        fake.base_url().as_str(),
        CLIENT_ID,
        &authorization.nonce,
    )?;
    mount_token_response(&fake, Some(&id_token)).await?;

    let completed = flow
        .complete(
            pending,
            PROVIDER_ID,
            REDIRECT_URI,
            AUTHORIZATION_CODE,
            &authorization.state,
        )
        .await?;

    assert_eq!(completed.identity().provider_subject(), SUBJECT);
    drop(rotated_jwks);
    Ok(())
}
