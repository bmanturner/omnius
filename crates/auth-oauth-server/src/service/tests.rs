use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    future::{Future, Ready, ready},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Waker},
    thread,
};

use omnius_auth_core::{AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_config::{DeploymentEnvironment, SecretString};

use super::*;
use crate::{
    config::{
        AuthorizationServerConfig, KeyAlgorithm, KeyState, ResourceConfig, ResourceScopeConfig,
        SigningKeyConfig,
    },
    crypto::{RsaPublicJwk, TEST_RSA_E, TEST_RSA_N, TEST_RSA_PRIVATE_KEY, TokenPepper},
    error::OAuthCryptoError,
    types::{AuthorizationRequestParts, PkceVerifier, Prompt, ResponseMode, ResponseType},
    verifier::{
        AccessTokenIdentity, AccessTokenLiveCheck, AccessTokenVerificationError,
        AccessTokenVerifier,
    },
};

const NOW_SECONDS: i64 = 1_800_000_000;
const OPAQUE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

#[derive(Debug)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Debug, Default)]
struct FixedEntropy(AtomicU8);

impl EntropySource for FixedEntropy {
    fn try_fill(&self, output: &mut [u8]) -> Result<(), OAuthCryptoError> {
        let start = self.0.fetch_add(1, Ordering::Relaxed);
        for (offset, byte) in output.iter_mut().enumerate() {
            *byte = start.wrapping_add(u8::try_from(offset).unwrap_or(0));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FakeState {
    session: Option<AuthorizationSubject>,
    covering_grant: Option<ExistingGrant>,
    authorization: Option<StoredAuthorization>,
    consumed_code: Option<ConsumedAuthorizationCode>,
    refresh_outcomes: VecDeque<RotateRefreshOutcome>,
    assertion_ids: HashSet<String>,
    live_access: bool,
    access_store_unavailable: bool,
    revocations: usize,
    decisions: usize,
    logout_allowed: bool,
}

#[derive(Debug)]
struct FakeStore {
    client: ResolvedClient,
    state: Mutex<FakeState>,
}

impl FakeStore {
    fn new(client: ResolvedClient, session: AuthorizationSubject) -> Self {
        Self {
            client,
            state: Mutex::new(FakeState {
                session: Some(session),
                covering_grant: None,
                authorization: None,
                consumed_code: None,
                refresh_outcomes: VecDeque::new(),
                assertion_ids: HashSet::new(),
                live_access: true,
                access_store_unavailable: false,
                revocations: 0,
                decisions: 0,
                logout_allowed: true,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[allow(refining_impl_trait)]
impl AccessTokenStateStore for FakeStore {
    fn authorize_access_token(
        &self,
        check: AccessTokenLiveCheck,
    ) -> Ready<Result<Option<AccessTokenIdentity>, OAuthStoreError>> {
        let state = self.state();
        if state.access_store_unavailable {
            return ready(Err(OAuthStoreError));
        }
        let identity = state
            .live_access
            .then(|| state.session.as_ref())
            .flatten()
            .filter(|subject| subject.public_subject == check.public_subject)
            .map(|subject| AccessTokenIdentity {
                subject_id: subject.principal.subject_id,
                kind: subject.principal.kind,
                tenant_id: subject.principal.tenant_id,
                authenticated_at: subject.principal.authenticated_at,
                assurance: subject.principal.assurance,
                public_subject: subject.public_subject.clone(),
                verified_email: subject.verified_email.clone(),
            });
        ready(Ok(identity))
    }
}

#[allow(refining_impl_trait)]
impl AuthorizationStore for FakeStore {
    fn resolve_client(
        &self,
        client_id: &ClientId,
    ) -> Ready<Result<Option<ResolvedClient>, OAuthStoreError>> {
        ready(Ok(
            (client_id == &self.client.client_id).then(|| self.client.clone())
        ))
    }

    fn authorize_session(
        &self,
        candidate: SessionCandidate,
    ) -> Ready<Result<Option<AuthorizationSubject>, OAuthStoreError>> {
        let state = self.state();
        ready(Ok(state
            .session
            .as_ref()
            .filter(|subject| {
                state.live_access && subject.principal.subject_id == candidate.subject_id
            })
            .cloned()))
    }

    fn find_covering_grant(
        &self,
        _query: CoveringGrantQuery,
    ) -> Ready<Result<Option<ExistingGrant>, OAuthStoreError>> {
        ready(Ok(self.state().covering_grant.clone()))
    }

    fn create_authorization(
        &self,
        command: CreateAuthorization,
    ) -> Ready<Result<(), OAuthStoreError>> {
        self.state().authorization = Some(command.authorization);
        ready(Ok(()))
    }

    fn load_authorization(
        &self,
        _handle_digest: BearerDigest,
        now: OffsetDateTime,
    ) -> Ready<Result<Option<StoredAuthorization>, OAuthStoreError>> {
        ready(Ok(self
            .state()
            .authorization
            .as_ref()
            .filter(|authorization| authorization.expires_at > now)
            .cloned()))
    }

    fn commit_authorization_decision(
        &self,
        command: CommitAuthorizationDecision,
    ) -> Ready<Result<CommitDecisionOutcome, OAuthStoreError>> {
        let mut state = self.state();
        if state.authorization.take().is_none() {
            return ready(Ok(CommitDecisionOutcome::Unavailable));
        }
        state.decisions += 1;
        ready(Ok(match command.decision {
            ConsentDecision::Approve
                if command.code_digest.is_some() && command.code_expires_at.is_some() =>
            {
                CommitDecisionOutcome::Approved
            }
            ConsentDecision::Deny if command.code_digest.is_none() => CommitDecisionOutcome::Denied,
            ConsentDecision::Approve | ConsentDecision::Deny => CommitDecisionOutcome::Unavailable,
        }))
    }

    fn authenticate_client_secret(
        &self,
        _client_id: &ClientId,
        secret: &str,
    ) -> Ready<Result<bool, OAuthStoreError>> {
        ready(Ok(secret == "correct-secret"))
    }

    fn accept_private_key_assertion(
        &self,
        _client_id: &ClientId,
        assertion: &PrivateKeyJwtAssertion,
    ) -> Ready<Result<bool, OAuthStoreError>> {
        let accepted = assertion.token() == "signed"
            && self.state().assertion_ids.insert(assertion.jwt_id.clone());
        ready(Ok(accepted))
    }

    fn consume_authorization_code(
        &self,
        _command: ConsumeAuthorizationCode,
    ) -> Ready<Result<ConsumeCodeOutcome, OAuthStoreError>> {
        ready(Ok(self
            .state()
            .consumed_code
            .take()
            .map_or(ConsumeCodeOutcome::Unavailable, |code| {
                ConsumeCodeOutcome::Consumed(Box::new(code))
            })))
    }

    fn rotate_refresh_token(
        &self,
        _command: RotateRefreshToken,
    ) -> Ready<Result<RotateRefreshOutcome, OAuthStoreError>> {
        ready(Ok(self
            .state()
            .refresh_outcomes
            .pop_front()
            .unwrap_or(RotateRefreshOutcome::Unavailable)))
    }

    fn revoke_token(
        &self,
        _client_id: &ClientId,
        _target: RevocationTarget,
        _now: OffsetDateTime,
    ) -> Ready<Result<(), OAuthStoreError>> {
        let mut state = self.state();
        state.live_access = false;
        state.revocations += 1;
        ready(Ok(()))
    }

    fn list_connected_grants(
        &self,
        _subject_id: SubjectId,
    ) -> Ready<Result<Vec<ConnectedGrant>, OAuthStoreError>> {
        ready(Ok(vec![ConnectedGrant {
            grant_id: grant_id(),
            client_name: self.client.display_name.clone(),
            resource: root_resource(),
            scopes: vec![test_scope("records:read")],
            consented_at: fixed_now(),
        }]))
    }

    fn revoke_connected_grant(
        &self,
        _subject_id: SubjectId,
        _grant_id: GrantId,
    ) -> Ready<Result<bool, OAuthStoreError>> {
        let mut state = self.state();
        state.live_access = false;
        ready(Ok(true))
    }

    fn logout_session(&self, command: LogoutSession) -> Ready<Result<bool, OAuthStoreError>> {
        let state = self.state();
        let matches = state.logout_allowed
            && state.session.as_ref().is_some_and(|subject| {
                subject.principal.subject_id == command.subject_id
                    && command
                        .public_subject
                        .as_ref()
                        .is_none_or(|public| public == &subject.public_subject)
            });
        ready(Ok(matches))
    }
}

type TestServer = AuthorizationServer<FakeStore, FixedClock, FixedEntropy>;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::yield_now(),
        }
    }
}

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS)
        .unwrap_or_else(|_| unreachable!("fixed timestamp is valid"))
}

fn uuid_v7(last: u8) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = last;
    Uuid::from_bytes(bytes)
}

fn subject_id() -> SubjectId {
    SubjectId::from_uuid(uuid_v7(1)).unwrap_or_else(|_| unreachable!("fixed subject UUID is v7"))
}

fn grant_id() -> GrantId {
    GrantId::from_uuid(uuid_v7(2)).unwrap_or_else(|_| unreachable!("fixed grant UUID is v7"))
}

fn test_scope(value: &str) -> Scope {
    Scope::new(value.to_owned()).unwrap_or_else(|_| unreachable!("test scope is valid"))
}

fn client_id() -> ClientId {
    ClientId::parse("client-1").unwrap_or_else(|_| unreachable!("test client is valid"))
}

fn root_resource() -> ResourceUri {
    ResourceUri::parse("https://issuer.example.test", true)
        .unwrap_or_else(|_| unreachable!("test resource is valid"))
}

fn userinfo_resource() -> ResourceUri {
    ResourceUri::parse("https://issuer.example.test/oauth/userinfo", true)
        .unwrap_or_else(|_| unreachable!("test resource is valid"))
}

fn redirect() -> RedirectUri {
    RedirectUri::parse("https://client.example.test/callback")
        .unwrap_or_else(|_| unreachable!("test redirect is valid"))
}

fn subject(email: Option<&str>, authenticated_at: OffsetDateTime) -> AuthorizationSubject {
    AuthorizationSubject {
        principal: Principal::new(
            subject_id(),
            PrincipalKind::User,
            None,
            AuthMethod::Session,
            authenticated_at,
            AssuranceLevel::Aal1,
            Vec::new(),
        )
        .unwrap_or_else(|_| unreachable!("test principal is valid")),
        public_subject: OPAQUE.to_owned(),
        verified_email: email.map(str::to_owned),
        acr: "urn:omnius:aal1".to_owned(),
        amr: vec!["pwd".to_owned()],
    }
}

fn resolved_client(method: TokenEndpointAuthMethod) -> ResolvedClient {
    let mut scopes = vec![
        test_scope("openid"),
        test_scope("email"),
        test_scope("offline_access"),
        test_scope("records:read"),
    ];
    scopes.sort_unstable();
    let mut resources = vec![root_resource(), userinfo_resource()];
    resources.sort_unstable();
    ResolvedClient {
        client_id: client_id(),
        display_name: "Example Client".to_owned(),
        display_origin: "https://client.example.test".to_owned(),
        redirect_uris: vec![
            redirect(),
            RedirectUri::parse("http://127.0.0.1:49152/callback?native=1")
                .unwrap_or_else(|_| unreachable!("test loopback redirect is valid")),
        ],
        post_logout_redirect_uris: vec![
            RedirectUri::parse("https://client.example.test/logout-complete")
                .unwrap_or_else(|_| unreachable!("test logout redirect is valid")),
        ],
        token_endpoint_auth_method: method,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes,
        resources,
    }
}

fn validated_config() -> Result<Arc<ValidatedAuthorizationServerConfig>, Box<dyn Error>> {
    let config = AuthorizationServerConfig {
        enabled: true,
        issuer: "https://issuer.example.test".to_owned(),
        token_pepper: Some(TokenPepper::parse(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )?),
        resources: vec![ResourceConfig {
            uri: root_resource().as_str().to_owned(),
            name: "Root API".to_owned(),
            description: "Root API resource".to_owned(),
            minimum_assurance: AssuranceLevel::Aal1,
            scopes: vec![ResourceScopeConfig {
                name: test_scope("records:read"),
                description: "Read records".to_owned(),
            }],
        }],
        signing_keys: vec![SigningKeyConfig {
            kid: "active-1".to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Active,
            public_jwk: RsaPublicJwk {
                kty: "RSA".to_owned(),
                public_key_use: "sig".to_owned(),
                key_ops: vec!["verify".to_owned()],
                alg: "RS256".to_owned(),
                kid: "active-1".to_owned(),
                n: TEST_RSA_N.to_owned(),
                e: TEST_RSA_E.to_owned(),
            },
            private_key_pkcs8_pem: Some(SecretString::from(TEST_RSA_PRIVATE_KEY.to_owned())),
            verification_until: None,
        }],
        ..AuthorizationServerConfig::default()
    };
    let validated = config
        .build_for(DeploymentEnvironment::Production, fixed_now())?
        .ok_or_else(|| std::io::Error::other("enabled test config was not built"))?;
    Ok(Arc::new(validated))
}

fn server_with(
    method: TokenEndpointAuthMethod,
) -> Result<(TestServer, Arc<FakeStore>), Box<dyn Error>> {
    let store = Arc::new(FakeStore::new(
        resolved_client(method),
        subject(None, fixed_now() - Duration::seconds(60)),
    ));
    let server = AuthorizationServer::new(
        validated_config()?,
        Arc::clone(&store),
        Arc::new(FixedClock(fixed_now())),
        Arc::new(FixedEntropy::default()),
    );
    Ok((server, store))
}

fn authorization_request(
    redirect_uri: RedirectUri,
    scopes: Vec<Scope>,
    resources: Vec<ResourceUri>,
    prompt: Option<Prompt>,
    max_age_seconds: Option<u64>,
) -> Result<AuthorizationRequestInput, Box<dyn Error>> {
    let verifier = PkceVerifier::parse(VERIFIER.to_owned())?;
    Ok(AuthorizationRequestInput::new(AuthorizationRequestParts {
        client_id: client_id(),
        redirect_uri,
        response_type: ResponseType::Code,
        response_mode: ResponseMode::Query,
        state: Some("secret-state".to_owned()),
        scopes,
        resources,
        pkce_challenge: verifier.challenge(),
        pkce_method: "S256".to_owned(),
        nonce: Some("nonce-1".to_owned()),
        prompt,
        max_age_seconds,
        expected_issuer: Some(IssuerUri::parse("https://issuer.example.test", true)?),
    })?)
}

fn api_request(
    redirect_uri: RedirectUri,
    prompt: Option<Prompt>,
) -> Result<AuthorizationRequestInput, Box<dyn Error>> {
    authorization_request(
        redirect_uri,
        vec![test_scope("records:read")],
        vec![root_resource()],
        prompt,
        None,
    )
}

fn context(
    resource: ResourceUri,
    scopes: Vec<Scope>,
    email: Option<&str>,
    refresh_allowed: bool,
) -> TokenGrantContext {
    TokenGrantContext {
        grant_id: grant_id(),
        client_id: client_id(),
        public_subject: OPAQUE.to_owned(),
        resource,
        scopes,
        auth_time: fixed_now() - Duration::seconds(60),
        acr: "urn:omnius:aal1".to_owned(),
        amr: vec!["pwd".to_owned()],
        nonce: Some("nonce-1".to_owned()),
        verified_email: email.map(str::to_owned),
        refresh_allowed,
    }
}

fn consumed_code(context: TokenGrantContext) -> ConsumedAuthorizationCode {
    ConsumedAuthorizationCode {
        client_id: client_id(),
        redirect_uri: redirect(),
        resource: context.resource.clone(),
        pkce_challenge: PkceVerifier::parse(VERIFIER.to_owned())
            .unwrap_or_else(|_| unreachable!("test verifier is valid"))
            .challenge(),
        context,
    }
}

fn none_authentication() -> ClientAuthentication {
    ClientAuthentication::None {
        client_id: client_id(),
    }
}

fn code_request(resource: ResourceUri, verifier: &str) -> AuthorizationCodeTokenRequest {
    AuthorizationCodeTokenRequest {
        client_authentication: none_authentication(),
        code: OPAQUE.to_owned(),
        redirect_uri: redirect(),
        code_verifier: PkceVerifier::parse(verifier.to_owned())
            .unwrap_or_else(|_| unreachable!("test verifier is valid")),
        resource: Some(resource),
    }
}

#[test]
fn authorization_errors_redirect_only_for_registered_redirects() -> Result<(), Box<dyn Error>> {
    let (server, _) = server_with(TokenEndpointAuthMethod::None)?;
    let registered = block_on(server.authorization_request_error(
        &client_id(),
        &redirect(),
        Some("correlation-state"),
        OAuthErrorCode::UnsupportedResponseType,
    ));
    assert_eq!(registered.code(), OAuthErrorCode::UnsupportedResponseType);
    let redirect = registered
        .redirect()
        .ok_or_else(|| std::io::Error::other("registered redirect did not receive an error"))?;
    assert_eq!(redirect.redirect_uri, self::redirect());
    assert_eq!(redirect.state.as_deref(), Some("correlation-state"));
    assert_eq!(redirect.issuer.as_str(), "https://issuer.example.test");

    let unsafe_redirect = RedirectUri::parse("https://evil.example.test/callback")?;
    let unsafe_error = block_on(server.authorization_request_error(
        &client_id(),
        &unsafe_redirect,
        Some("must-not-echo"),
        OAuthErrorCode::InvalidRequest,
    ));
    assert_eq!(unsafe_error.code(), OAuthErrorCode::InvalidRequest);
    assert!(unsafe_error.redirect().is_none());
    Ok(())
}

#[test]
fn expected_issuer_mismatch_is_rejected_before_persistence() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    let verifier = PkceVerifier::parse(VERIFIER.to_owned())?;
    let request = AuthorizationRequestInput::new(AuthorizationRequestParts {
        client_id: client_id(),
        redirect_uri: redirect(),
        response_type: ResponseType::Code,
        response_mode: ResponseMode::Query,
        state: Some("issuer-state".to_owned()),
        scopes: vec![test_scope("records:read")],
        resources: vec![root_resource()],
        pkce_challenge: verifier.challenge(),
        pkce_method: "S256".to_owned(),
        nonce: None,
        prompt: None,
        max_age_seconds: None,
        expected_issuer: Some(IssuerUri::parse(
            "https://different-issuer.example.test",
            true,
        )?),
    })?;
    let error = block_on(server.begin_authorization(request, None))
        .err()
        .ok_or_else(|| std::io::Error::other("mismatched issuer was accepted"))?;
    assert_eq!(error.code(), OAuthErrorCode::InvalidRequest);
    assert!(error.redirect().is_some());
    assert!(store.state().authorization.is_none());
    Ok(())
}

#[test]
fn redirect_safety_and_loopback_exception_are_exact() -> Result<(), Box<dyn Error>> {
    let (server, _) = server_with(TokenEndpointAuthMethod::None)?;
    let unsafe_request = api_request(
        RedirectUri::parse("https://evil.example.test/callback")?,
        None,
    )?;
    let error = block_on(server.begin_authorization(unsafe_request, None))
        .err()
        .ok_or_else(|| std::io::Error::other("unsafe redirect was accepted"))?;
    assert_eq!(error.redirect(), None);

    let registered = RedirectUri::parse("http://127.0.0.1:49152/callback?native=1")?;
    let substituted = RedirectUri::parse("http://127.0.0.1:61234/callback?native=1")?;
    assert!(registered.matches_registered(&substituted));
    let changed_query = RedirectUri::parse("http://127.0.0.1:61234/callback?native=2")?;
    assert!(!registered.matches_registered(&changed_query));
    assert!(RedirectUri::parse("http://localhost:61234/callback").is_err());
    Ok(())
}

#[test]
fn prompt_none_returns_login_consent_or_direct_success() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    store.state().session = None;
    let login_error =
        block_on(server.begin_authorization(api_request(redirect(), Some(Prompt::None))?, None))
            .err()
            .ok_or_else(|| std::io::Error::other("prompt none displayed login"))?;
    assert_eq!(login_error.code(), OAuthErrorCode::LoginRequired);
    assert!(login_error.redirect().is_some());

    store.state().session = Some(subject(None, fixed_now()));
    let consent_error = block_on(server.begin_authorization(
        api_request(redirect(), Some(Prompt::None))?,
        Some(SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now(),
        }),
    ))
    .err()
    .ok_or_else(|| std::io::Error::other("prompt none displayed consent"))?;
    assert_eq!(consent_error.code(), OAuthErrorCode::ConsentRequired);

    store.state().covering_grant = Some(ExistingGrant {
        grant_id: grant_id(),
        resource: root_resource(),
        scopes: vec![test_scope("records:read")],
        offline_access_consented: false,
    });
    let success = block_on(server.begin_authorization(
        api_request(redirect(), Some(Prompt::None))?,
        Some(SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now(),
        }),
    ))?;
    let BeginAuthorizationResult::Redirect(success) = success else {
        return Err(std::io::Error::other("covering grant was not reused").into());
    };
    assert!(success.code.is_some());
    assert_eq!(success.issuer.as_str(), "https://issuer.example.test");
    Ok(())
}

#[test]
fn offline_access_requires_explicit_consent_and_interaction_hides_state()
-> Result<(), Box<dyn Error>> {
    let (server, _) = server_with(TokenEndpointAuthMethod::None)?;
    let scopes = vec![test_scope("offline_access"), test_scope("openid")];
    let error = block_on(server.begin_authorization(
        authorization_request(redirect(), scopes.clone(), Vec::new(), None, None)?,
        Some(SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now(),
        }),
    ))
    .err()
    .ok_or_else(|| std::io::Error::other("offline access skipped consent"))?;
    assert_eq!(error.code(), OAuthErrorCode::InvalidScope);

    let begun = block_on(server.begin_authorization(
        authorization_request(redirect(), scopes, Vec::new(), Some(Prompt::Consent), None)?,
        Some(SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now(),
        }),
    ))?;
    let BeginAuthorizationResult::Interaction(begun) = begun else {
        return Err(std::io::Error::other("offline access did not require interaction").into());
    };
    let interaction = block_on(server.interaction(begun.handle.expose()))?;
    let serialized = serde_json::to_string(&interaction)?;
    assert!(!serialized.contains("secret-state"));
    assert_eq!(interaction.requirement, InteractionRequirement::Consent);
    Ok(())
}

#[test]
fn max_age_zero_requires_newer_authentication() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    let begun = block_on(server.begin_authorization(
        authorization_request(
            redirect(),
            vec![test_scope("records:read")],
            vec![root_resource()],
            None,
            Some(0),
        )?,
        Some(SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now() - Duration::seconds(60),
        }),
    ))?;
    let BeginAuthorizationResult::Interaction(begun) = begun else {
        return Err(std::io::Error::other("max_age zero did not require login").into());
    };
    let stale = block_on(server.decide(
        begun.handle.expose(),
        SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now() - Duration::seconds(60),
        },
        ConsentDecision::Approve,
    ))
    .err()
    .ok_or_else(|| std::io::Error::other("stale authentication was accepted"))?;
    assert_eq!(stale.code(), OAuthErrorCode::LoginRequired);

    store.state().session = Some(subject(None, fixed_now()));
    let approved = block_on(server.decide(
        begun.handle.expose(),
        SessionCandidate {
            subject_id: subject_id(),
            authenticated_at: fixed_now(),
        },
        ConsentDecision::Approve,
    ))?;
    assert!(approved.code.is_some());
    Ok(())
}

#[test]
fn failed_pkce_consumes_recognized_code_once() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    store.state().consumed_code = Some(consumed_code(context(
        root_resource(),
        vec![test_scope("records:read")],
        None,
        false,
    )));
    let wrong_verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
    let first = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        root_resource(),
        wrong_verifier,
    ))))
    .err()
    .ok_or_else(|| std::io::Error::other("bad PKCE was accepted"))?;
    assert_eq!(first.code(), OAuthErrorCode::InvalidGrant);
    let second = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        root_resource(),
        VERIFIER,
    ))))
    .err()
    .ok_or_else(|| std::io::Error::other("consumed code was accepted"))?;
    assert_eq!(second.code(), OAuthErrorCode::InvalidGrant);
    Ok(())
}

#[test]
fn concurrent_code_exchange_has_one_winner() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    store.state().consumed_code = Some(consumed_code(context(
        root_resource(),
        vec![test_scope("records:read")],
        None,
        false,
    )));
    let first_server = server.clone();
    let second_server = server;
    let first = thread::spawn(move || {
        block_on(
            first_server.token(TokenRequest::AuthorizationCode(code_request(
                root_resource(),
                VERIFIER,
            ))),
        )
    });
    let second = thread::spawn(move || {
        block_on(
            second_server.token(TokenRequest::AuthorizationCode(code_request(
                root_resource(),
                VERIFIER,
            ))),
        )
    });
    let first = first
        .join()
        .unwrap_or_else(|_| panic!("first exchange panicked"));
    let second = second
        .join()
        .unwrap_or_else(|_| panic!("second exchange panicked"));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    Ok(())
}

#[test]
fn client_authentication_is_exclusive_and_assertion_jti_is_one_use() -> Result<(), Box<dyn Error>> {
    let mixed = ClientAuthentication::try_from(ClientAuthenticationParts {
        public_client_id: Some(client_id()),
        basic: Some((
            client_id(),
            ClientSecret::parse("correct-secret".to_owned())?,
        )),
        private_key_jwt: None,
    });
    assert_eq!(
        mixed.err().map(|error| error.code()),
        Some(OAuthErrorCode::InvalidClient)
    );

    let (server, store) = server_with(TokenEndpointAuthMethod::PrivateKeyJwt)?;
    assert!(
        server
            .issue_tokens(
                context(
                    root_resource(),
                    vec![test_scope("records:read")],
                    None,
                    false,
                ),
                None,
            )
            .is_ok(),
        "private-key client token signing must use the common issuer path",
    );
    let assertion = PrivateKeyJwtAssertion::new(
        "signed".to_owned(),
        client_id(),
        client_id(),
        "https://issuer.example.test/oauth/token".to_owned(),
        "assertion-1".to_owned(),
        fixed_now() - Duration::seconds(1),
        fixed_now() + Duration::seconds(60),
    )?;
    let authentication = ClientAuthentication::PrivateKeyJwt {
        client_id: client_id(),
        assertion,
    };
    store.state().consumed_code = Some(consumed_code(context(
        root_resource(),
        vec![test_scope("records:read")],
        None,
        false,
    )));
    let mut request = code_request(root_resource(), VERIFIER);
    request.client_authentication = authentication.clone();
    let first_exchange = block_on(server.token(TokenRequest::AuthorizationCode(request)));
    assert!(first_exchange.is_ok(), "{first_exchange:?}");

    store.state().consumed_code = Some(consumed_code(context(
        root_resource(),
        vec![test_scope("records:read")],
        None,
        false,
    )));
    let mut replay = code_request(root_resource(), VERIFIER);
    replay.client_authentication = authentication;
    let error = block_on(server.token(TokenRequest::AuthorizationCode(replay)))
        .err()
        .ok_or_else(|| std::io::Error::other("assertion replay was accepted"))?;
    assert_eq!(error.code(), OAuthErrorCode::InvalidClient);
    Ok(())
}

#[test]
fn refresh_rotation_narrows_and_reuse_is_rejected() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    store
        .state()
        .refresh_outcomes
        .push_back(RotateRefreshOutcome::Rotated(Box::new(context(
            root_resource(),
            vec![test_scope("offline_access"), test_scope("records:read")],
            None,
            true,
        ))));
    store
        .state()
        .refresh_outcomes
        .push_back(RotateRefreshOutcome::ReuseDetected);
    let request = RefreshTokenRequest {
        client_authentication: none_authentication(),
        refresh_token: OPAQUE.to_owned(),
        scopes: Some(vec![
            test_scope("offline_access"),
            test_scope("records:read"),
        ]),
        resource: Some(root_resource()),
    };
    let response = block_on(server.token(TokenRequest::RefreshToken(request.clone())))?;
    assert!(response.refresh_token.is_some());
    assert_eq!(
        response.scopes,
        vec![test_scope("offline_access"), test_scope("records:read")]
    );
    let reuse = block_on(server.token(TokenRequest::RefreshToken(request)))
        .err()
        .ok_or_else(|| std::io::Error::other("refresh reuse was accepted"))?;
    assert_eq!(reuse.code(), OAuthErrorCode::InvalidGrant);
    Ok(())
}

#[test]
fn unknown_revocation_succeeds_and_live_revocation_is_immediate() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    let unknown = block_on(server.revoke(RevocationRequest {
        client_authentication: none_authentication(),
        token: "not-a-token".to_owned(),
        token_type_hint: None,
        audience: None,
    }))?;
    assert_eq!(unknown.sensitivity, ResponseSensitivity::NoStore);
    assert_eq!(store.state().revocations, 0);

    store.state().consumed_code = Some(consumed_code(context(
        root_resource(),
        vec![test_scope("records:read")],
        None,
        false,
    )));
    let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        root_resource(),
        VERIFIER,
    ))))?;
    let verifier = AccessTokenVerifier::new(
        Arc::new(validated_config()?.signing_keys().clone()),
        IssuerUri::parse("https://issuer.example.test", true)?,
        root_resource(),
        vec![test_scope("records:read")],
        Arc::clone(&store),
        Arc::new(FixedClock(fixed_now())),
    )?;
    assert!(block_on(verifier.verify(&response.access_token)).is_ok());
    block_on(server.revoke(RevocationRequest {
        client_authentication: none_authentication(),
        token: response.access_token.clone(),
        token_type_hint: Some(TokenTypeHint::AccessToken),
        audience: Some(root_resource()),
    }))?;
    assert_eq!(
        block_on(verifier.verify(&response.access_token)).err(),
        Some(AccessTokenVerificationError::Inactive)
    );
    Ok(())
}

#[test]
fn userinfo_rejections_use_invalid_token() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    let malformed = block_on(server.userinfo("not-a-jwt"))
        .err()
        .ok_or_else(|| std::io::Error::other("malformed UserInfo token was accepted"))?;
    assert_eq!(malformed.code(), OAuthErrorCode::InvalidToken);

    store.state().consumed_code = Some(consumed_code(context(
        root_resource(),
        vec![test_scope("records:read")],
        None,
        false,
    )));
    let wrong_audience = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        root_resource(),
        VERIFIER,
    ))))?;
    let rejected_audience = block_on(server.userinfo(&wrong_audience.access_token))
        .err()
        .ok_or_else(|| std::io::Error::other("wrong-audience UserInfo token was accepted"))?;
    assert_eq!(rejected_audience.code(), OAuthErrorCode::InvalidToken);

    store.state().consumed_code = Some(consumed_code(context(
        userinfo_resource(),
        vec![test_scope("email")],
        None,
        false,
    )));
    let insufficient_scope = block_on(server.token(TokenRequest::AuthorizationCode(
        code_request(userinfo_resource(), VERIFIER),
    )))?;
    let rejected_scope = block_on(server.userinfo(&insufficient_scope.access_token))
        .err()
        .ok_or_else(|| std::io::Error::other("UserInfo token without openid was accepted"))?;
    assert_eq!(rejected_scope.code(), OAuthErrorCode::InvalidToken);

    store.state().consumed_code = Some(consumed_code(context(
        userinfo_resource(),
        vec![test_scope("openid")],
        None,
        false,
    )));
    let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        userinfo_resource(),
        VERIFIER,
    ))))?;
    let expired_server = AuthorizationServer::new(
        validated_config()?,
        Arc::clone(&store),
        Arc::new(FixedClock(fixed_now() + Duration::hours(2))),
        Arc::new(FixedEntropy::default()),
    );
    let expired = block_on(expired_server.userinfo(&response.access_token))
        .err()
        .ok_or_else(|| std::io::Error::other("expired UserInfo token was accepted"))?;
    assert_eq!(expired.code(), OAuthErrorCode::InvalidToken);
    store.state().access_store_unavailable = true;
    let unavailable = block_on(server.userinfo(&response.access_token))
        .err()
        .ok_or_else(|| std::io::Error::other("unavailable UserInfo store was ignored"))?;
    assert_eq!(unavailable.code(), OAuthErrorCode::ServerError);
    store.state().access_store_unavailable = false;

    store.state().live_access = false;
    let revoked = block_on(server.userinfo(&response.access_token))
        .err()
        .ok_or_else(|| std::io::Error::other("revoked UserInfo token was accepted"))?;
    assert_eq!(revoked.code(), OAuthErrorCode::InvalidToken);
    Ok(())
}

#[test]
fn id_token_and_userinfo_share_subject_without_unverified_email() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    store.state().consumed_code = Some(consumed_code(context(
        userinfo_resource(),
        vec![test_scope("email"), test_scope("openid")],
        None,
        false,
    )));
    let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        userinfo_resource(),
        VERIFIER,
    ))))?;
    let id_token = response
        .id_token
        .as_deref()
        .ok_or_else(|| std::io::Error::other("OIDC exchange omitted ID Token"))?;
    let claims = validated_config()?.signing_keys().verify_id_token(
        id_token,
        &IssuerUri::parse("https://issuer.example.test", true)?,
        &client_id(),
        Some("nonce-1"),
        fixed_now(),
    )?;
    assert_eq!(claims.email(), None);
    let userinfo = block_on(server.userinfo(&response.access_token))?;
    assert_eq!(userinfo.sub, claims.subject());
    assert_eq!(userinfo.email, None);
    assert_eq!(userinfo.email_verified, None);
    Ok(())
}

#[test]
fn logout_redirect_requires_valid_hint_and_exact_registration() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    store.state().consumed_code = Some(consumed_code(context(
        userinfo_resource(),
        vec![test_scope("openid")],
        None,
        false,
    )));
    let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
        userinfo_resource(),
        VERIFIER,
    ))))?;
    let id_token = response
        .id_token
        .ok_or_else(|| std::io::Error::other("OIDC exchange omitted ID Token"))?;
    let registered = RedirectUri::parse("https://client.example.test/logout-complete")?;
    let result = block_on(server.logout(LogoutRequest {
        subject_id: subject_id(),
        id_token_hint: Some(IdTokenHint::new(
            id_token.clone(),
            client_id(),
            Some("nonce-1".to_owned()),
        )?),
        post_logout_redirect_uri: Some(registered.clone()),
        state: Some("logout-state".to_owned()),
    }))?;
    assert_eq!(result.redirect_uri, Some(registered));
    assert_eq!(result.state.as_deref(), Some("logout-state"));

    let rejected = block_on(server.logout(LogoutRequest {
        subject_id: subject_id(),
        id_token_hint: Some(IdTokenHint::new(
            id_token,
            client_id(),
            Some("nonce-1".to_owned()),
        )?),
        post_logout_redirect_uri: Some(RedirectUri::parse(
            "https://client.example.test/not-registered",
        )?),
        state: Some("must-not-return".to_owned()),
    }))
    .err()
    .ok_or_else(|| std::io::Error::other("unregistered logout redirect was accepted"))?;
    assert_eq!(rejected.code(), OAuthErrorCode::InvalidRequest);
    Ok(())
}

#[test]
fn connected_grant_revocation_removes_live_authority() -> Result<(), Box<dyn Error>> {
    let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
    let grants = block_on(server.connected_grants(subject_id()))?;
    assert_eq!(grants.len(), 1);
    assert!(block_on(
        server.revoke_connected_grant(subject_id(), grant_id())
    )?);
    assert!(!store.state().live_access);
    Ok(())
}
