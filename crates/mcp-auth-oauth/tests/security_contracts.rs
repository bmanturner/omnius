//! Security contracts for MCP protected-resource authentication and authorization.

use std::{
    error::Error,
    future::{Future, ready},
    sync::Arc,
};

use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_auth_oauth_server::{
    AccessTokenClaims, AccessTokenClaimsInput, AccessTokenIdentity, AccessTokenLiveCheck,
    AccessTokenStateStore, ClientId, Clock, GrantId, IssuerUri, JwtId, KeyAlgorithm, KeyState,
    OAuthStoreError, ResourceUri, RsaPublicJwk, SigningKeyConfig, SigningKeyRing,
    VerifiedAccessToken,
};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_config::SecretString;
use omnius_mcp_auth_oauth::{
    BearerAuthenticationError, BearerTokenAuthenticator, CapabilityVisibility,
    LiveStateRequirement, MAX_PROTECTED_RESOURCE_METADATA_BYTES, McpAuthenticatedIdentity,
    McpHeaderAllowlist, McpHeaderError, McpOperation, McpOperationAuthorizer, McpProtectedResource,
    McpResourceIdentity, OAuthAccessTokenAuthenticator, OperationAuthorizationRequest,
    OperationGuard, OperationRequirements, PROTECTED_RESOURCE_METADATA_CACHE_CONTROL,
    PROTECTED_RESOURCE_METADATA_CONTENT_TYPE, PROTECTED_RESOURCE_METADATA_MAX_AGE_SECONDS,
    ProtectedResourceError, TenantGuard, TokenDecisionInput, authenticate_bearer_request,
    extract_bearer_credential,
};
use time::{Duration, OffsetDateTime};

const RESOURCE: &str = "https://api.example.com/mcp";
const ISSUER: &str = "https://issuer.example.com";
const METADATA_URL: &str = "https://api.example.com/.well-known/oauth-protected-resource/mcp";
const TEST_RSA_PRIVATE_KEY: &str = include_str!("../../auth-jwt/tests/test_rsa_key.pem");
const TEST_RSA_N: &str = "ibepHr39ICr8VUuIFq8Eo0YwJPK5ho4EGyMmhmycy365cohGDI2gvZxpfSeB7N00Xjbx1kC789yiO0_VM-uuWf_olDXzRtkJqW7ukGZ1ThRCqGfOsVDizeTYGkeGz4MU_8l4E1ehu5_CZBDsyBqfuNq5FtnDBjJU_o7PeTIHHtyNDwgMFFWo3aLNxW7j-kDTd_zHrxRc0XG9vIbZRLh35_mu9oiUcsjpeGifE4uhkjIT3I2co4m6Rk-_loFBrs6DAhmZpISKDiTrk0ain6nOoYTe3W3fTHpDDjiyxQAi7m51GHdWvkmiAf_nL7zmmGZIuuTTWNCh2T3Kcju-1T_6VQ";
const PUBLIC_SUBJECT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn scope(value: &str) -> Result<Scope, Box<dyn Error>> {
    Ok(Scope::new(value.to_owned())?)
}

fn profile() -> Result<McpProtectedResource, Box<dyn Error>> {
    let identity = McpResourceIdentity::parse(RESOURCE, ISSUER, true)?;
    Ok(McpProtectedResource::new(
        identity,
        vec![scope("mcp:write")?, scope("mcp:read")?],
    )?)
}

fn requirements(
    profile: &McpProtectedResource,
    names: &[&str],
) -> Result<OperationRequirements, Box<dyn Error>> {
    let required = names
        .iter()
        .copied()
        .map(scope)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(profile.operation_requirements(required)?)
}

fn principal(
    auth_method: AuthMethod,
    tenant_id: Option<TenantId>,
    scopes: &[&str],
) -> Result<Principal, Box<dyn Error>> {
    let subject_id: SubjectId = "01890f2a-0000-7000-8000-000000000001".parse()?;
    let scopes = scopes
        .iter()
        .copied()
        .map(scope)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Principal::new(
        subject_id,
        PrincipalKind::User,
        tenant_id,
        auth_method,
        OffsetDateTime::from_unix_timestamp(1_700_000_000)?,
        AssuranceLevel::Aal2,
        scopes,
    )?)
}

fn authenticated_identity(
    principal: Principal,
    client_id: &str,
) -> Result<McpAuthenticatedIdentity, Box<dyn Error>> {
    let scopes = principal.scopes.clone();
    Ok(McpAuthenticatedIdentity::from_verified_access_token(
        IssuerUri::parse(ISSUER, true)?,
        VerifiedAccessToken {
            principal,
            public_subject: PUBLIC_SUBJECT.to_owned(),
            verified_email: Some("verified-user@example.com".to_owned()),
            client_id: ClientId::parse(client_id)?,
            grant_id: GrantId::new(),
            jwt_id: JwtId::new(),
            audience: ResourceUri::parse(RESOURCE, true)?,
            scopes,
        },
    )?)
}

fn bearer_headers(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static(value));
    headers
}

#[derive(Clone)]
struct FixtureAuthenticator {
    full_identity: McpAuthenticatedIdentity,
    read_identity: McpAuthenticatedIdentity,
}

impl FixtureAuthenticator {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            full_identity: authenticated_identity(
                principal(AuthMethod::Jwt, None, &["mcp:read", "mcp:write"])?,
                "fixture-full-client",
            )?,
            read_identity: authenticated_identity(
                principal(AuthMethod::Jwt, None, &["mcp:read"])?,
                "fixture-read-client",
            )?,
        })
    }
}

impl BearerTokenAuthenticator for FixtureAuthenticator {
    fn authenticate<'a>(
        &'a self,
        credential: omnius_mcp_auth_oauth::BearerCredential<'a>,
        decision: TokenDecisionInput<'a>,
    ) -> impl Future<Output = Result<McpAuthenticatedIdentity, BearerAuthenticationError>> + Send + 'a
    {
        let result = if decision.issuer().as_str() != ISSUER
            || decision.audience().as_str() != RESOURCE
            || decision.resource().as_str() != RESOURCE
            || decision.live_state() != LiveStateRequirement::Required
            || decision.required_scopes().is_empty()
        {
            Err(BearerAuthenticationError)
        } else {
            match credential.expose_secret() {
                "valid-token" => Ok(self.full_identity.clone()),
                "read-only-token" => Ok(self.read_identity.clone()),
                _ => Err(BearerAuthenticationError),
            }
        };
        ready(result)
    }
}

struct FixedAuthorizer(Decision);

impl McpOperationAuthorizer<str> for FixedAuthorizer {
    fn authorize(&self, request: OperationAuthorizationRequest<'_, str>) -> Decision {
        assert!(!request.target().is_empty());
        assert_eq!(request.principal().tenant_id, request.tenant_id());
        assert_eq!(request.identity().principal(), request.principal());
        self.0
    }
}

struct ClientAuthorizer(ClientId);

impl McpOperationAuthorizer<str> for ClientAuthorizer {
    fn authorize(&self, request: OperationAuthorizationRequest<'_, str>) -> Decision {
        if request.identity().client_id() == &self.0 {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::NotEntitled)
        }
    }
}

#[derive(Debug)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Debug)]
struct ProductionStore {
    active: bool,
    principal: Principal,
}

impl AccessTokenStateStore for ProductionStore {
    fn authorize_access_token(
        &self,
        check: AccessTokenLiveCheck,
    ) -> impl Future<Output = Result<Option<AccessTokenIdentity>, OAuthStoreError>> + Send {
        let identity = (self.active
            && check.public_subject == PUBLIC_SUBJECT
            && check.client_id.as_str() == "mcp-test-client"
            && check.audience.as_str() == RESOURCE
            && check.scopes.len() == 2
            && check.scopes[0].as_str() == "mcp:read"
            && check.scopes[1].as_str() == "mcp:write")
            .then(|| AccessTokenIdentity {
                subject_id: self.principal.subject_id,
                kind: self.principal.kind,
                tenant_id: self.principal.tenant_id,
                authenticated_at: self.principal.authenticated_at,
                assurance: self.principal.assurance,
                public_subject: check.public_subject,
                verified_email: Some("verified-user@example.com".to_owned()),
            });
        ready(Ok(identity))
    }
}

fn signing_key_ring(now: OffsetDateTime) -> Result<SigningKeyRing, Box<dyn Error>> {
    let public_jwk = RsaPublicJwk {
        kty: "RSA".to_owned(),
        public_key_use: "sig".to_owned(),
        key_ops: vec!["verify".to_owned()],
        alg: "RS256".to_owned(),
        kid: "mcp-test-key".to_owned(),
        n: TEST_RSA_N.to_owned(),
        e: "AQAB".to_owned(),
    };
    Ok(SigningKeyRing::from_config(
        &[SigningKeyConfig {
            kid: "mcp-test-key".to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Active,
            public_jwk,
            private_key_pkcs8_pem: Some(SecretString::from(TEST_RSA_PRIVATE_KEY.to_owned())),
            verification_until: None,
        }],
        now,
    )?)
}

fn access_token_claims(
    issuer: IssuerUri,
    audience: ResourceUri,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<AccessTokenClaims, Box<dyn Error>> {
    Ok(AccessTokenClaims::new(AccessTokenClaimsInput {
        issuer,
        subject: PUBLIC_SUBJECT.to_owned(),
        audience,
        expires_at,
        not_before: issued_at,
        issued_at,
        jwt_id: JwtId::new(),
        client_id: ClientId::parse("mcp-test-client")?,
        grant_id: GrantId::new(),
        scopes: vec![scope("mcp:read")?, scope("mcp:write")?],
        auth_time: issued_at,
        acr: "aal2".to_owned(),
        amr: vec!["pwd".to_owned()],
    })?)
}

fn bearer_headers_for_token(token: &str) -> Result<HeaderMap, Box<dyn Error>> {
    let presentation = format!("Bearer {token}");
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_bytes(presentation.as_bytes())?,
    );
    Ok(headers)
}

#[test]
fn protected_resource_metadata_is_exact_canonical_and_bounded() -> Result<(), Box<dyn Error>> {
    let profile = profile()?;
    let expected = concat!(
        "{\"resource\":\"https://api.example.com/mcp\",",
        "\"authorization_servers\":[\"https://issuer.example.com\"],",
        "\"scopes_supported\":[\"mcp:read\",\"mcp:write\"],",
        "\"bearer_methods_supported\":[\"header\"],",
        "\"resource_signing_alg_values_supported\":[\"RS256\"]}"
    );

    assert_eq!(
        profile.identity().protected_resource_metadata_url(),
        METADATA_URL
    );
    assert_eq!(profile.metadata_json(), expected.as_bytes());
    assert_eq!(
        profile.metadata().authorization_servers(),
        &[ISSUER.to_owned()]
    );
    assert_eq!(
        profile.metadata().bearer_methods_supported(),
        &["header".to_owned()]
    );
    assert_eq!(PROTECTED_RESOURCE_METADATA_CONTENT_TYPE, "application/json");
    assert_eq!(
        PROTECTED_RESOURCE_METADATA_CACHE_CONTROL,
        "public, max-age=300, must-revalidate"
    );
    const { assert!(PROTECTED_RESOURCE_METADATA_MAX_AGE_SECONDS <= 300) };
    assert!(profile.metadata_json().len() <= MAX_PROTECTED_RESOURCE_METADATA_BYTES);
    Ok(())
}

#[test]
fn resource_identity_rejects_relative_query_and_non_resource_scope() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        McpResourceIdentity::parse("/mcp", ISSUER, true),
        Err(ProtectedResourceError::InvalidResource)
    );
    assert_eq!(
        McpResourceIdentity::parse("https://api.example.com/mcp?tenant=a", ISSUER, true),
        Err(ProtectedResourceError::InvalidResource)
    );
    let identity = McpResourceIdentity::parse(RESOURCE, ISSUER, true)?;
    assert!(matches!(
        McpProtectedResource::new(identity, vec![scope("offline_access")?]),
        Err(ProtectedResourceError::NonResourceScope)
    ));
    Ok(())
}

#[tokio::test]
async fn missing_bearer_returns_exact_discovery_challenge() -> Result<(), Box<dyn Error>> {
    let profile = profile()?;
    let requirements = requirements(&profile, &["mcp:read"])?;
    let rejection = authenticate_bearer_request(
        &profile,
        &requirements,
        &FixtureAuthenticator::new()?,
        &HeaderMap::new(),
        None,
    )
    .await
    .err()
    .ok_or("request unexpectedly authenticated")?;

    assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejection.www_authenticate().as_str(),
        concat!(
            "Bearer resource_metadata=\"",
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            "\", scope=\"mcp:read\""
        )
    );
    Ok(())
}

#[tokio::test]
async fn bearer_presentations_use_rfc_6750_spacing_and_exact_statuses() -> Result<(), Box<dyn Error>>
{
    let profile = profile()?;
    let requirements = requirements(&profile, &["mcp:read"])?;
    let authenticator = FixtureAuthenticator::new()?;
    let invalid_request = concat!(
        "Bearer error=\"invalid_request\", resource_metadata=\"",
        "https://api.example.com/.well-known/oauth-protected-resource/mcp",
        "\", scope=\"mcp:read\""
    );

    let mut duplicate = bearer_headers("Bearer valid-token");
    duplicate.append(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer second-token"),
    );
    let invalid_presentations = [
        (bearer_headers("Basic credential"), None),
        (bearer_headers("Bearer token with-space"), None),
        (bearer_headers("Bearer\tvalid-token"), None),
        (bearer_headers(" Bearer valid-token"), None),
        (bearer_headers("Bearer valid-token "), None),
        (duplicate, None),
        (
            bearer_headers("Bearer valid-token"),
            Some("access_token=query-token"),
        ),
        (HeaderMap::new(), Some("access_token=query-token")),
    ];

    for (index, (headers, query)) in invalid_presentations.into_iter().enumerate() {
        let rejection =
            authenticate_bearer_request(&profile, &requirements, &authenticator, &headers, query)
                .await
                .err()
                .ok_or("invalid presentation unexpectedly authenticated")?;
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST, "case {index}");
        assert_eq!(
            rejection.www_authenticate().as_str(),
            invalid_request,
            "case {index}"
        );
    }

    let repeated_sp = authenticate_bearer_request(
        &profile,
        &requirements,
        &authenticator,
        &bearer_headers("bEaReR   valid-token"),
        None,
    )
    .await?;
    assert_eq!(repeated_sp.client_id().as_str(), "fixture-full-client");

    let invalid_token = authenticate_bearer_request(
        &profile,
        &requirements,
        &authenticator,
        &bearer_headers("Bearer unknown-token"),
        None,
    )
    .await
    .err()
    .ok_or("unknown token unexpectedly authenticated")?;
    assert_eq!(invalid_token.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid_token.www_authenticate().as_str(),
        concat!(
            "Bearer error=\"invalid_token\", resource_metadata=\"",
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            "\", scope=\"mcp:read\""
        )
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one verifier contract exercises all identity evidence and negative security states"
)]
#[tokio::test]
async fn production_verifier_retains_evidence_and_rejects_invalid_security_state()
-> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let profile = Arc::new(profile()?);
    let requirements = requirements(&profile, &["mcp:read"])?;
    let ring = Arc::new(signing_key_ring(now)?);
    let expected_principal = principal(AuthMethod::Jwt, None, &["mcp:read", "mcp:write"])?;
    let active_authenticator = OAuthAccessTokenAuthenticator::new(
        Arc::clone(&profile),
        Arc::clone(&ring),
        Arc::new(ProductionStore {
            active: true,
            principal: expected_principal.clone(),
        }),
        Arc::new(FixedClock(now)),
    )?;
    let issuer = IssuerUri::parse(ISSUER, true)?;
    let audience = ResourceUri::parse(RESOURCE, true)?;
    let valid_claims = access_token_claims(
        issuer.clone(),
        audience.clone(),
        now,
        now + Duration::minutes(10),
    )?;
    let valid_token = ring.sign_access_token(&valid_claims)?.expose_once();
    let wrong_issuer = ring
        .sign_access_token(&access_token_claims(
            IssuerUri::parse("https://wrong-issuer.example.com", true)?,
            audience.clone(),
            now,
            now + Duration::minutes(10),
        )?)?
        .expose_once();
    let wrong_resource = ring
        .sign_access_token(&access_token_claims(
            issuer.clone(),
            ResourceUri::parse("https://other-api.example.com/mcp", true)?,
            now,
            now + Duration::minutes(10),
        )?)?
        .expose_once();
    let expired = ring
        .sign_access_token(&access_token_claims(
            issuer,
            audience,
            now - Duration::minutes(10),
            now - Duration::seconds(1),
        )?)?
        .expose_once();
    let mut tampered = valid_token.clone();
    let signature_index = tampered
        .rfind('.')
        .map(|index| index + 1)
        .filter(|index| *index < tampered.len())
        .ok_or("signed token had no signature")?;
    let original = *tampered
        .as_bytes()
        .get(signature_index)
        .ok_or("signed token had no signature byte")?;
    let replacement = if original == b'A' { "B" } else { "A" };
    tampered.replace_range(signature_index..=signature_index, replacement);
    let expected_challenge = concat!(
        "Bearer error=\"invalid_token\", resource_metadata=\"",
        "https://api.example.com/.well-known/oauth-protected-resource/mcp",
        "\", scope=\"mcp:read\""
    );

    for token in [wrong_issuer, wrong_resource, expired, tampered] {
        let headers = bearer_headers_for_token(&token)?;
        let rejection = authenticate_bearer_request(
            &profile,
            &requirements,
            &active_authenticator,
            &headers,
            None,
        )
        .await
        .err()
        .ok_or("invalid production token unexpectedly authenticated")?;
        assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(rejection.www_authenticate().as_str(), expected_challenge);
    }

    let revoked_authenticator = OAuthAccessTokenAuthenticator::new(
        Arc::clone(&profile),
        Arc::clone(&ring),
        Arc::new(ProductionStore {
            active: false,
            principal: expected_principal.clone(),
        }),
        Arc::new(FixedClock(now)),
    )?;
    let revoked_headers = bearer_headers_for_token(&valid_token)?;
    let revoked = authenticate_bearer_request(
        &profile,
        &requirements,
        &revoked_authenticator,
        &revoked_headers,
        None,
    )
    .await
    .err()
    .ok_or("revoked production token unexpectedly authenticated")?;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(revoked.www_authenticate().as_str(), expected_challenge);

    let valid_headers = bearer_headers_for_token(&valid_token)?;
    let authenticated = authenticate_bearer_request(
        &profile,
        &requirements,
        &active_authenticator,
        &valid_headers,
        None,
    )
    .await?;
    assert_eq!(authenticated.principal(), &expected_principal);
    assert_eq!(authenticated.issuer().as_str(), valid_claims.issuer());
    assert_eq!(authenticated.audience().as_str(), valid_claims.audience());
    assert_eq!(authenticated.resource().as_str(), RESOURCE);
    assert_eq!(authenticated.client_id().as_str(), valid_claims.client_id());
    assert_eq!(authenticated.grant_id().as_uuid(), valid_claims.grant_id());
    assert_eq!(authenticated.jwt_id().as_uuid(), valid_claims.jwt_id());
    assert_eq!(authenticated.public_subject(), valid_claims.subject());
    assert_eq!(
        authenticated.verified_email(),
        Some("verified-user@example.com")
    );
    assert_eq!(authenticated.scopes(), expected_principal.scopes.as_slice());
    Ok(())
}

#[tokio::test]
async fn insufficient_scope_returns_exact_403_with_every_required_scope()
-> Result<(), Box<dyn Error>> {
    let profile = profile()?;
    let requirements = requirements(&profile, &["mcp:write", "mcp:read"])?;
    let headers = bearer_headers("Bearer read-only-token");
    let rejection = authenticate_bearer_request(
        &profile,
        &requirements,
        &FixtureAuthenticator::new()?,
        &headers,
        None,
    )
    .await
    .err()
    .ok_or("request unexpectedly authenticated")?;

    assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        rejection.www_authenticate().as_str(),
        concat!(
            "Bearer error=\"insufficient_scope\", resource_metadata=\"",
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            "\", scope=\"mcp:read mcp:write\""
        )
    );
    Ok(())
}

#[tokio::test]
async fn valid_exact_resource_token_returns_typed_identity_evidence() -> Result<(), Box<dyn Error>>
{
    let profile = profile()?;
    let requirements = requirements(&profile, &["mcp:read"])?;
    let authenticator = FixtureAuthenticator::new()?;
    let expected = authenticator.full_identity.clone();
    let actual = authenticate_bearer_request(
        &profile,
        &requirements,
        &authenticator,
        &bearer_headers("Bearer valid-token"),
        None,
    )
    .await?;

    assert_eq!(actual, expected);
    assert_eq!(actual.principal(), expected.principal());
    assert_eq!(actual.client_id().as_str(), "fixture-full-client");
    Ok(())
}

#[tokio::test]
async fn authenticator_cannot_substitute_a_session_or_api_key_fallback()
-> Result<(), Box<dyn Error>> {
    let profile = profile()?;
    let requirements = requirements(&profile, &["mcp:read"])?;
    let authenticator = FixtureAuthenticator::new()?;
    assert!(
        authenticated_identity(
            principal(AuthMethod::Session, None, &["mcp:read", "mcp:write"])?,
            "session-fallback-client",
        )
        .is_err()
    );
    let session = authenticate_bearer_request(
        &profile,
        &requirements,
        &authenticator,
        &bearer_headers("Bearer session-principal"),
        None,
    )
    .await
    .err()
    .ok_or("session principal unexpectedly authenticated")?;
    let mut api_key_only = HeaderMap::new();
    api_key_only.insert("x-api-key", HeaderValue::from_static("secret-api-key"));
    let api_key =
        authenticate_bearer_request(&profile, &requirements, &authenticator, &api_key_only, None)
            .await
            .err()
            .ok_or("API key unexpectedly authenticated")?;

    assert_eq!(session.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(api_key.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[test]
fn header_allowlist_rejects_auth_host_hop_proxy_trace_and_duplicates() {
    for name in [
        "authorization",
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-authorization",
        "proxy",
        "forwarded",
        "x-forwarded-host",
        "x-proxy-user",
        "x-envoy-original-path",
        "x-original-host",
        "x-original-proto",
        "x-original-scheme",
        "front-end-https",
        "x-url-scheme",
        "traceparent",
        "tracestate",
        "baggage",
        "b3",
        "x-b3-traceid",
        "x-datadog-trace-id",
        "x-datadog-parent-id",
        "x-request-id",
        "x-mcp-header",
    ] {
        assert_eq!(
            McpHeaderAllowlist::new([name]),
            Err(McpHeaderError::Forbidden),
            "{name}"
        );
    }
    assert_eq!(
        McpHeaderAllowlist::new(["x-safe", "X-Safe"]),
        Err(McpHeaderError::Duplicate)
    );
}

#[test]
fn outbound_projection_never_propagates_authorization_and_redacts_values()
-> Result<(), Box<dyn Error>> {
    let allowlist = McpHeaderAllowlist::new(["x-provider-mode", "x-provider-key"])?;
    assert_eq!(
        allowlist.validate([("Authorization", "Bearer inbound-secret")]),
        Err(McpHeaderError::Forbidden)
    );
    assert_eq!(
        allowlist.validate([("x-provider-mode", "safe"), ("X-Provider-Mode", "override")]),
        Err(McpHeaderError::Duplicate)
    );

    let projection = allowlist.validate([
        ("x-provider-mode", "safe"),
        ("x-provider-key", "provider-secret"),
    ])?;
    let debug = format!("{projection:?}");
    let header_map_debug = format!("{:?}", projection.headers());
    assert!(!projection.headers().contains_key(AUTHORIZATION));
    assert!(
        projection
            .headers()
            .get("x-provider-key")
            .is_some_and(HeaderValue::is_sensitive)
    );
    assert!(!debug.contains("provider-secret"));
    assert!(!header_map_debug.contains("provider-secret"));
    assert!(debug.contains("[REDACTED]"));
    Ok(())
}

#[test]
fn tenant_private_and_ordinary_denials_do_not_enumerate_capabilities() -> Result<(), Box<dyn Error>>
{
    let tenant_a: TenantId = "01890f2a-0000-7000-8000-00000000000a".parse()?;
    let tenant_b: TenantId = "01890f2a-0000-7000-8000-00000000000b".parse()?;
    let identity = authenticated_identity(
        principal(AuthMethod::Jwt, Some(tenant_a), &["mcp:read"])?,
        "tenant-client",
    )?;

    let tenant_denial = TenantGuard
        .authorize(&identity, Some(tenant_b))
        .err()
        .ok_or("cross-tenant request unexpectedly allowed")?;
    let tenant = TenantGuard.authorize(&identity, Some(tenant_a))?;
    let allow = FixedAuthorizer(Decision::Allow);
    let deny = FixedAuthorizer(Decision::Deny(DenyReason::NotEntitled));
    let private_denial = OperationGuard
        .authorize(
            tenant,
            McpOperation::ReadResource,
            CapabilityVisibility::TenantPrivate(tenant_b),
            "private-capability",
            &allow,
        )
        .err()
        .ok_or("private capability unexpectedly disclosed")?;
    let policy_denial = OperationGuard
        .authorize(
            tenant,
            McpOperation::ReadResource,
            CapabilityVisibility::Public,
            "public-capability",
            &deny,
        )
        .err()
        .ok_or("ordinary authorization unexpectedly allowed")?;

    assert_eq!(tenant_denial, private_denial);
    assert_eq!(private_denial, policy_denial);
    assert_eq!(format!("{policy_denial:?}"), "OperationDenied([REDACTED])");
    Ok(())
}

#[test]
fn every_mcp_operation_requires_an_explicit_allow_decision() -> Result<(), Box<dyn Error>> {
    let identity = authenticated_identity(
        principal(AuthMethod::Jwt, None, &["mcp:read"])?,
        "operation-client",
    )?;
    let tenant = TenantGuard.authorize(&identity, None)?;
    let deny = FixedAuthorizer(Decision::Deny(DenyReason::MissingPolicy));
    let allow = FixedAuthorizer(Decision::Allow);
    for operation in [
        McpOperation::ListResources,
        McpOperation::ReadResource,
        McpOperation::ListPrompts,
        McpOperation::GetPrompt,
        McpOperation::ListTools,
        McpOperation::CallTool,
    ] {
        assert!(
            OperationGuard
                .authorize(
                    tenant,
                    operation,
                    CapabilityVisibility::Public,
                    "capability",
                    &deny,
                )
                .is_err()
        );
    }
    let allowed = OperationGuard.authorize(
        tenant,
        McpOperation::CallTool,
        CapabilityVisibility::Public,
        "capability",
        &allow,
    )?;
    assert_eq!(allowed.operation(), McpOperation::CallTool);
    assert_eq!(allowed.identity(), &identity);
    assert_eq!(allowed.principal(), identity.principal());
    Ok(())
}

#[test]
fn ordinary_policy_distinguishes_verified_clients_for_the_same_principal()
-> Result<(), Box<dyn Error>> {
    let principal = principal(AuthMethod::Jwt, None, &["mcp:read"])?;
    let allowed_identity = authenticated_identity(principal.clone(), "allowed-oauth-client")?;
    let denied_identity = authenticated_identity(principal, "different-oauth-client")?;
    assert_eq!(allowed_identity.principal(), denied_identity.principal());
    assert_ne!(allowed_identity.client_id(), denied_identity.client_id());

    let policy = ClientAuthorizer(ClientId::parse("allowed-oauth-client")?);
    let allowed_tenant = TenantGuard.authorize(&allowed_identity, None)?;
    let denied_tenant = TenantGuard.authorize(&denied_identity, None)?;
    let allowed = OperationGuard.authorize(
        allowed_tenant,
        McpOperation::CallTool,
        CapabilityVisibility::Public,
        "client-bound-capability",
        &policy,
    )?;
    let denied = OperationGuard.authorize(
        denied_tenant,
        McpOperation::CallTool,
        CapabilityVisibility::Public,
        "client-bound-capability",
        &policy,
    );

    assert_eq!(
        allowed.identity().client_id().as_str(),
        "allowed-oauth-client"
    );
    assert_eq!(denied.err(), Some(omnius_mcp_auth_oauth::OperationDenied));
    Ok(())
}

#[test]
fn credential_rejection_and_identity_debug_output_never_contains_secret_values()
-> Result<(), Box<dyn Error>> {
    let headers = bearer_headers("Bearer top-secret-token");
    let credential = extract_bearer_credential(&headers, None)?;
    let credential_debug = format!("{credential:?}");
    let error_debug = format!("{BearerAuthenticationError:?}");
    let identity = authenticated_identity(
        principal(AuthMethod::Jwt, None, &["mcp:read"])?,
        "secret-client-identifier",
    )?;
    let identity_debug = format!("{identity:?}");

    assert!(!credential_debug.contains("top-secret-token"));
    assert!(credential_debug.contains("[REDACTED]"));
    assert!(!error_debug.contains("top-secret-token"));
    assert_eq!(identity_debug, "McpAuthenticatedIdentity([REDACTED])");
    assert!(!identity_debug.contains("secret-client-identifier"));
    assert!(!identity_debug.contains("verified-user@example.com"));
    assert!(!identity_debug.contains(PUBLIC_SUBJECT));
    Ok(())
}
