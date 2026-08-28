use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use metrics::counter;
use omnius_auth_core::{Principal, PrincipalKind, SubjectId};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _};
use omnius_outbound_http::{Method, OutboundHttpClients, PolicyClass, Url};
use openidconnect::{
    AccessToken, AccessTokenHash, AsyncHttpClient, AuthorizationCode, ClaimsVerificationError,
    ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest,
    HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse as _, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, SignatureVerificationError, TokenResponse as _,
    core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::config::{OidcConfig, OidcConfigError, OidcProviderConfig};

const MAX_CALLBACK_CODE_BYTES: usize = 4_096;
const MAX_CALLBACK_STATE_BYTES: usize = 1_024;
const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_REDIRECT_URI_BYTES: usize = 2_048;
const MAX_NONCE_BYTES: usize = 1_024;
const MIN_PKCE_VERIFIER_BYTES: usize = 43;
const MAX_PKCE_VERIFIER_BYTES: usize = 128;
const MAX_VERIFIED_SUBJECT_BYTES: usize = 255;
const MAX_HTTP_URL_BYTES: usize = 4_096;
const MAX_HTTP_BODY_BYTES: usize = 16 * 1_024;
const MAX_HTTP_HEADERS: usize = 64;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1_024;
const MIN_PROVIDER_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const REDACTED: &str = "[REDACTED]";

type ProviderClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// The account operation bound to one OIDC authorization attempt.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowPurpose {
    /// Authenticate an already-linked external identity.
    Login,
    /// Explicitly link the verified external identity to this canonical subject.
    Link {
        /// Canonical subject that initiated the linking flow.
        subject_id: SubjectId,
        /// Latest callback time allowed by the initiating authentication proof.
        proof_expires_at: OffsetDateTime,
    },
}

impl fmt::Debug for FlowPurpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login => formatter.write_str("Login"),
            Self::Link { .. } => formatter
                .debug_struct("Link")
                .field("subject_id", &REDACTED)
                .finish(),
        }
    }
}

/// Serializable server-side state for exactly one authorization callback.
///
/// This value owns the nonce and PKCE verifier and is intentionally not cloneable. Its serialized
/// representation contains protocol secrets and must never be logged or returned to a browser.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingAuthorization {
    pub(crate) provider_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) state_digest: [u8; 32],
    pub(crate) nonce: String,
    pub(crate) pkce_verifier: String,
    pub(crate) purpose: FlowPurpose,
    pub(crate) expires_at: OffsetDateTime,
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("provider_id", &self.provider_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("state_digest", &REDACTED)
            .field("nonce", &REDACTED)
            .field("pkce_verifier", &REDACTED)
            .field("purpose", &self.purpose)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Browser redirect and server-side state created for one authorization attempt.
pub struct AuthorizationStart {
    pub(crate) authorization_url: Url,
    pub(crate) pending: PendingAuthorization,
}

impl fmt::Debug for AuthorizationStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationStart")
            .field("authorization_url", &REDACTED)
            .field("pending", &REDACTED)
            .finish()
    }
}

/// Verified OIDC identity material safe to pass to the identity store.
pub struct VerifiedIdentity {
    pub(crate) provider: String,
    pub(crate) provider_subject: String,
    pub(crate) authenticated_at: OffsetDateTime,
}

impl VerifiedIdentity {
    /// Returns the exact verified issuer used as the external identity namespace.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// Returns the subject from the cryptographically verified ID token.
    #[must_use]
    pub fn provider_subject(&self) -> &str {
        &self.provider_subject
    }
    /// Returns the local time at which ID-token verification completed.
    #[must_use]
    pub const fn authenticated_at(&self) -> OffsetDateTime {
        self.authenticated_at
    }
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIdentity")
            .field("provider", &self.provider)
            .field("provider_subject", &REDACTED)
            .field("authenticated_at", &self.authenticated_at)
            .finish()
    }
}

/// Successfully verified authorization result and its bound account operation.
pub struct CompletedAuthorization {
    pub(crate) identity: VerifiedIdentity,
    pub(crate) purpose: FlowPurpose,
}

impl CompletedAuthorization {
    /// Borrows the verified external identity.
    #[must_use]
    pub const fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }
    /// Borrows the operation selected before the browser redirect.
    #[must_use]
    pub const fn purpose(&self) -> &FlowPurpose {
        &self.purpose
    }
    /// Consumes the result into the verified identity and bound operation.
    #[must_use]
    pub fn into_parts(self) -> (VerifiedIdentity, FlowPurpose) {
        (self.identity, self.purpose)
    }
}

impl fmt::Debug for CompletedAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedAuthorization")
            .field("identity", &self.identity)
            .field("purpose", &self.purpose)
            .finish()
    }
}

struct Provider {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect: RedirectUrl,
    redirect_uri: String,
    scopes: Arc<[String]>,
    client: RwLock<ProviderClient>,
    http: OidcHttpClient,
    refresh: Mutex<RefreshState>,
}

impl Provider {
    fn client(&self) -> Result<ProviderClient, OidcFlowError> {
        self.client
            .read()
            .map(|client| client.clone())
            .map_err(|_| OidcFlowError::InternalState)
    }

    async fn refresh_client(&self) -> Result<bool, OidcFlowError> {
        let mut refresh = self.refresh.lock().await;
        let now = Instant::now();
        if let Some((completed_at, succeeded)) = refresh.last_completed
            && now.duration_since(completed_at) < MIN_PROVIDER_REFRESH_INTERVAL
        {
            counter!("omnius_auth_oidc_provider_refresh_total", "result" => "coalesced")
                .increment(1);
            return if succeeded {
                Ok(false)
            } else {
                Err(OidcFlowError::ProviderRefreshUnavailable)
            };
        }

        let Ok(metadata) =
            CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http).await
        else {
            refresh.last_completed = Some((Instant::now(), false));
            counter!("omnius_auth_oidc_provider_refresh_total", "result" => "failure").increment(1);
            return Err(OidcFlowError::ProviderRefreshUnavailable);
        };
        let authorization_allowed = self
            .http
            .approve_url(metadata.authorization_endpoint().as_str())
            .await;
        if metadata.issuer() != &self.issuer
            || metadata.token_endpoint().is_none()
            || !authorization_allowed
        {
            refresh.last_completed = Some((Instant::now(), false));
            counter!("omnius_auth_oidc_provider_refresh_total", "result" => "rejected")
                .increment(1);
            return Err(OidcFlowError::ProviderRefreshUnavailable);
        }
        let client = configured_client(
            metadata,
            self.client_id.clone(),
            self.client_secret.clone(),
            self.redirect.clone(),
        );
        *self
            .client
            .write()
            .map_err(|_| OidcFlowError::InternalState)? = client;
        refresh.last_completed = Some((Instant::now(), true));
        counter!("omnius_auth_oidc_provider_refresh_total", "result" => "success").increment(1);
        Ok(true)
    }
}

struct RefreshState {
    last_completed: Option<(Instant, bool)>,
}

/// OIDC authorization-code protocol engine backed by discovered provider metadata.
#[derive(Clone)]
pub struct OidcFlow {
    providers: Arc<HashMap<String, Arc<Provider>>>,
    pending_flow_ttl: Duration,
    link_proof_max_age: Duration,
}

impl fmt::Debug for OidcFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcFlow")
            .field("provider_count", &self.providers.len())
            .field("pending_flow_ttl", &self.pending_flow_ttl)
            .field("link_proof_max_age", &self.link_proof_max_age)
            .finish_non_exhaustive()
    }
}

/// Pending authorization atomically consumed from shared server-side storage.
pub struct TakenAuthorization {
    pub(crate) pending: PendingAuthorization,
}

impl fmt::Debug for TakenAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TakenAuthorization([REDACTED])")
    }
}

impl OidcFlow {
    /// Validates configuration, discovers each provider with redirects disabled, and builds clients.
    ///
    /// # Errors
    /// Returns a value-free build failure when configuration or provider metadata is invalid.
    pub async fn initialize(
        config: &OidcConfig,
        deployment: DeploymentEnvironment,
        http: OutboundHttpClients,
    ) -> Result<Self, OidcBuildError> {
        config
            .validate_for(deployment)
            .map_err(OidcBuildError::Config)?;
        if !config.enabled {
            return Err(OidcBuildError::Disabled);
        }
        let http = OidcHttpClient {
            inner: http,
            response_body_limit_bytes: config.response_body_limit_bytes,
        };
        let mut providers = HashMap::with_capacity(config.providers.len());
        for configured in &config.providers {
            let provider = build_provider(configured, http.clone()).await?;
            if providers
                .insert(configured.provider_id.clone(), Arc::new(provider))
                .is_some()
            {
                return Err(OidcBuildError::ConfigInvariant);
            }
        }
        Ok(Self {
            providers: Arc::new(providers),
            pending_flow_ttl: config.pending_flow_ttl,
            link_proof_max_age: config.link_proof_max_age,
        })
    }

    /// Starts a login authorization-code flow.
    ///
    /// # Errors
    /// Returns a value-free failure if the provider is unknown or client state is unavailable.
    pub fn start_login(&self, provider_id: &str) -> Result<AuthorizationStart, OidcFlowError> {
        self.start(provider_id, FlowPurpose::Login)
    }

    /// Starts an account-link flow bound to a recently authenticated user principal.
    ///
    /// # Errors
    /// Returns [`OidcFlowError::LinkProofRequired`] unless `principal` is a human user whose
    /// authentication time is within the configured proof window.
    pub fn start_link(
        &self,
        provider_id: &str,
        principal: &Principal,
    ) -> Result<AuthorizationStart, OidcFlowError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let authenticated_at = principal.authenticated_at.unix_timestamp();
        let max_age = i64::try_from(self.link_proof_max_age.as_secs())
            .map_err(|_| OidcFlowError::InternalState)?;
        if principal.kind != PrincipalKind::User
            || authenticated_at > now.saturating_add(30)
            || now.saturating_sub(authenticated_at) > max_age
        {
            return Err(OidcFlowError::LinkProofRequired);
        }
        let proof_expires_at = principal
            .authenticated_at
            .checked_add(time::Duration::seconds(max_age))
            .ok_or(OidcFlowError::InternalState)?;
        self.start(
            provider_id,
            FlowPurpose::Link {
                subject_id: principal.subject_id,
                proof_expires_at,
            },
        )
    }

    fn start(
        &self,
        provider_id: &str,
        purpose: FlowPurpose,
    ) -> Result<AuthorizationStart, OidcFlowError> {
        let result = self.start_inner(provider_id, purpose);
        counter!("omnius_auth_oidc_authorizations_started_total", "result" => result.as_ref().map_or_else(|error| error.label(), |_| "success")).increment(1);
        result
    }

    fn start_inner(
        &self,
        provider_id: &str,
        purpose: FlowPurpose,
    ) -> Result<AuthorizationStart, OidcFlowError> {
        if !valid_provider_input(provider_id) {
            return Err(OidcFlowError::UnknownProvider);
        }
        let provider = self
            .providers
            .get(provider_id)
            .ok_or(OidcFlowError::UnknownProvider)?;
        let client = provider.client()?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in provider
            .scopes
            .iter()
            .filter(|scope| scope.as_str() != "openid")
        {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (authorization_url, state, nonce) = request.set_pkce_challenge(challenge).url();
        let pending = PendingAuthorization {
            provider_id: provider_id.to_owned(),
            redirect_uri: provider.redirect_uri.clone(),
            state_digest: state_digest(state.secret()),
            nonce: nonce.secret().to_owned(),
            pkce_verifier: verifier.secret().to_owned(),
            purpose,
            expires_at: OffsetDateTime::now_utc() + self.pending_flow_ttl,
        };
        Ok(AuthorizationStart {
            authorization_url,
            pending,
        })
    }

    /// Completes one authorization-code callback from atomically consumed pending state.
    ///
    /// Identity is returned only from a verified ID token. Key failures permit one rate-limited
    /// metadata/JWKS refresh and validation retry without re-exchanging the code.
    ///
    /// # Errors
    /// Returns a stable value-free callback, exchange, verification, refresh, or state failure.
    pub async fn complete(
        &self,
        authorization: TakenAuthorization,
        provider_id: &str,
        redirect_uri: &str,
        authorization_code: &str,
        state: &str,
    ) -> Result<CompletedAuthorization, OidcFlowError> {
        let TakenAuthorization { pending } = authorization;
        let result = self
            .complete_inner(
                pending,
                provider_id,
                redirect_uri,
                authorization_code,
                state,
            )
            .await;
        counter!("omnius_auth_oidc_authorizations_completed_total", "result" => result.as_ref().map_or_else(|error| error.label(), |_| "success")).increment(1);
        result
    }

    async fn complete_inner(
        &self,
        pending: PendingAuthorization,
        provider_id: &str,
        redirect_uri: &str,
        code: &str,
        state: &str,
    ) -> Result<CompletedAuthorization, OidcFlowError> {
        if !valid_provider_input(provider_id)
            || !valid_callback_value(redirect_uri, MAX_REDIRECT_URI_BYTES)
            || !valid_callback_value(code, MAX_CALLBACK_CODE_BYTES)
            || !valid_callback_value(state, MAX_CALLBACK_STATE_BYTES)
            || !valid_provider_input(&pending.provider_id)
            || !valid_callback_value(&pending.redirect_uri, MAX_REDIRECT_URI_BYTES)
            || !valid_callback_value(&pending.nonce, MAX_NONCE_BYTES)
            || !valid_pkce_verifier(&pending.pkce_verifier)
        {
            return Err(OidcFlowError::MalformedCallback);
        }
        let now = OffsetDateTime::now_utc();
        if now >= pending.expires_at {
            return Err(OidcFlowError::Expired);
        }
        if pending.expires_at > now + self.pending_flow_ttl {
            return Err(OidcFlowError::MalformedCallback);
        }
        if let FlowPurpose::Link {
            proof_expires_at, ..
        } = &pending.purpose
        {
            let latest_valid_proof = now
                .checked_add(time::Duration::seconds(30))
                .and_then(|deadline| {
                    deadline.checked_add(time::Duration::try_from(self.link_proof_max_age).ok()?)
                })
                .ok_or(OidcFlowError::InternalState)?;
            if *proof_expires_at > latest_valid_proof {
                return Err(OidcFlowError::MalformedCallback);
            }
            if now >= *proof_expires_at {
                return Err(OidcFlowError::LinkProofRequired);
            }
        }
        if pending.provider_id != provider_id || pending.redirect_uri != redirect_uri {
            return Err(OidcFlowError::ContextMismatch);
        }
        if !state_digest_matches(&pending.state_digest, &state_digest(state)) {
            return Err(OidcFlowError::StateMismatch);
        }
        let provider = self
            .providers
            .get(provider_id)
            .ok_or(OidcFlowError::UnknownProvider)?;
        if provider.redirect_uri != redirect_uri {
            return Err(OidcFlowError::ContextMismatch);
        }
        let client = provider.client()?;
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| OidcFlowError::ProviderMetadataRejected)?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&provider.http)
            .await
            .map_err(|_| OidcFlowError::TokenExchangeFailed)?;
        let id_token = response.id_token().ok_or(OidcFlowError::MissingIdToken)?;
        let nonce = Nonce::new(pending.nonce);
        let (issuer, subject) = match verify_id_token(
            &client,
            id_token,
            response.access_token(),
            &nonce,
            &provider.issuer,
        ) {
            Ok(identity) => identity,
            Err(VerifyFailure::Refreshable) => {
                provider.refresh_client().await?;
                verify_id_token(
                    &provider.client()?,
                    id_token,
                    response.access_token(),
                    &nonce,
                    &provider.issuer,
                )
                .map_err(|_| OidcFlowError::IdTokenRejected)?
            }
            Err(VerifyFailure::Rejected) => return Err(OidcFlowError::IdTokenRejected),
        };
        Ok(CompletedAuthorization {
            identity: VerifiedIdentity {
                provider: issuer,
                provider_subject: subject,
                authenticated_at: OffsetDateTime::now_utc(),
            },
            purpose: pending.purpose,
        })
    }
}

async fn build_provider(
    config: &OidcProviderConfig,
    http: OidcHttpClient,
) -> Result<Provider, OidcBuildError> {
    let issuer =
        IssuerUrl::new(config.issuer.clone()).map_err(|_| OidcBuildError::ConfigInvariant)?;
    let redirect = RedirectUrl::new(config.redirect_uri.clone())
        .map_err(|_| OidcBuildError::ConfigInvariant)?;
    let metadata = CoreProviderMetadata::discover_async(issuer.clone(), &http)
        .await
        .map_err(|_| OidcBuildError::ProviderDiscovery)?;
    let authorization_allowed = http
        .approve_url(metadata.authorization_endpoint().as_str())
        .await;
    if metadata.issuer() != &issuer || metadata.token_endpoint().is_none() || !authorization_allowed
    {
        return Err(OidcBuildError::ProviderMetadataRejected);
    }
    let client_id = ClientId::new(config.client_id.clone());
    let client_secret = ClientSecret::new(config.client_secret.expose_secret().to_owned());
    let client = configured_client(
        metadata,
        client_id.clone(),
        client_secret.clone(),
        redirect.clone(),
    );
    Ok(Provider {
        issuer,
        client_id,
        client_secret,
        redirect,
        redirect_uri: config.redirect_uri.clone(),
        scopes: config.scopes.clone().into(),
        client: RwLock::new(client),
        http,
        refresh: Mutex::new(RefreshState {
            last_completed: None,
        }),
    })
}

fn configured_client(
    metadata: CoreProviderMetadata,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect: RedirectUrl,
) -> ProviderClient {
    CoreClient::from_provider_metadata(metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect)
}

fn verify_id_token(
    client: &ProviderClient,
    id_token: &CoreIdToken,
    access_token: &AccessToken,
    nonce: &Nonce,
    issuer: &IssuerUrl,
) -> Result<(String, String), VerifyFailure> {
    let verifier = client.id_token_verifier();
    let claims = id_token.claims(&verifier, nonce).map_err(|error| {
        if refreshable(&error) {
            VerifyFailure::Refreshable
        } else {
            VerifyFailure::Rejected
        }
    })?;
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let signing_algorithm = id_token
            .signing_alg()
            .map_err(|_| VerifyFailure::Rejected)?;
        let signing_key = id_token
            .signing_key(&verifier)
            .map_err(|_| VerifyFailure::Rejected)?;
        let actual_access_token_hash =
            AccessTokenHash::from_token(access_token, signing_algorithm, signing_key)
                .map_err(|_| VerifyFailure::Rejected)?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(VerifyFailure::Rejected);
        }
    }
    if claims.issuer() != issuer {
        return Err(VerifyFailure::Rejected);
    }
    let subject = claims.subject().as_str();
    if subject.is_empty()
        || subject.len() > MAX_VERIFIED_SUBJECT_BYTES
        || subject.chars().any(char::is_control)
    {
        return Err(VerifyFailure::Rejected);
    }
    Ok((claims.issuer().as_str().to_owned(), subject.to_owned()))
}

fn refreshable(error: &ClaimsVerificationError) -> bool {
    matches!(
        error,
        ClaimsVerificationError::SignatureVerification(SignatureVerificationError::NoMatchingKey)
    )
}

enum VerifyFailure {
    Refreshable,
    Rejected,
}

fn valid_provider_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
fn valid_callback_value(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_pkce_verifier(value: &str) -> bool {
    (MIN_PKCE_VERIFIER_BYTES..=MAX_PKCE_VERIFIER_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}
pub(crate) fn state_digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn state_digest_matches(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[derive(Clone)]
struct OidcHttpClient {
    inner: OutboundHttpClients,
    response_body_limit_bytes: usize,
}

impl<'client> AsyncHttpClient<'client> for OidcHttpClient {
    type Error = OidcHttpClientError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'client>>;
    fn call(&'client self, request: HttpRequest) -> Self::Future {
        Box::pin(async move { self.execute(request).await })
    }
}

impl OidcHttpClient {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, OidcHttpClientError> {
        let (parts, body) = request.into_parts();
        let uri = parts.uri.to_string();
        if uri.len() > MAX_HTTP_URL_BYTES || body.len() > MAX_HTTP_BODY_BYTES {
            return Err(OidcHttpClientError::RequestRejected);
        }
        let url = Url::parse(&uri).map_err(|_| OidcHttpClientError::RequestRejected)?;
        let approved = self
            .inner
            .approve(url)
            .await
            .map_err(|_| OidcHttpClientError::RequestRejected)?;
        if parts.headers.len() > MAX_HTTP_HEADERS
            || header_bytes(&parts.headers) > MAX_HTTP_HEADER_BYTES
        {
            return Err(OidcHttpClientError::RequestRejected);
        }
        let method = Method::from_bytes(parts.method.as_str().as_bytes())
            .map_err(|_| OidcHttpClientError::RequestRejected)?;
        let mut builder = self
            .inner
            .request(PolicyClass::NoRedirect, method, &approved)
            .body(body);
        for (name, value) in &parts.headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        let request = builder
            .build()
            .map_err(|_| OidcHttpClientError::RequestRejected)?;
        let response = self
            .inner
            .execute_bounded_with_limit(request, self.response_body_limit_bytes)
            .await
            .map_err(|_| OidcHttpClientError::ProviderUnavailable)?;
        if response.headers().len() > MAX_HTTP_HEADERS
            || header_bytes(response.headers()) > MAX_HTTP_HEADER_BYTES
        {
            return Err(OidcHttpClientError::ResponseRejected);
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut result = HttpResponse::new(response.into_body());
        *result.status_mut() = status;
        *result.headers_mut() = headers;
        Ok(result)
    }
}

impl OidcHttpClient {
    async fn approve_url(&self, value: &str) -> bool {
        if value.len() > MAX_HTTP_URL_BYTES {
            return false;
        }
        let Ok(url) = Url::parse(value) else {
            return false;
        };
        self.inner.approve(url).await.is_ok()
    }
}

fn header_bytes(headers: &openidconnect::http::HeaderMap) -> usize {
    headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
    })
}

#[derive(Debug, Error)]
enum OidcHttpClientError {
    #[error("OIDC HTTP request was rejected")]
    RequestRejected,
    #[error("OIDC provider is unavailable")]
    ProviderUnavailable,
    #[error("OIDC HTTP response was rejected")]
    ResponseRejected,
}

/// Stable, value-free OIDC client construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OidcBuildError {
    /// Static OIDC configuration is invalid.
    #[error("OIDC configuration is invalid")]
    Config(#[source] OidcConfigError),
    /// OIDC was not enabled.
    #[error("OIDC is disabled")]
    Disabled,
    /// A provider discovery request or bounded response failed.
    #[error("OIDC provider discovery failed")]
    ProviderDiscovery,
    /// Discovered metadata omitted a required endpoint or did not exactly match its issuer.
    #[error("OIDC provider metadata was rejected")]
    ProviderMetadataRejected,
    /// Validated configuration could not be represented by the protocol library.
    #[error("OIDC configuration invariant failed")]
    ConfigInvariant,
}

/// Stable, value-free OIDC authorization failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OidcFlowError {
    /// The selected provider is unknown or malformed.
    #[error("OIDC provider is unavailable")]
    UnknownProvider,
    /// A callback value is empty, oversized, or malformed.
    #[error("OIDC callback is malformed")]
    MalformedCallback,
    /// The callback provider or exact redirect URI differs from the pending flow.
    #[error("OIDC callback context does not match")]
    ContextMismatch,
    /// The callback state does not match the pending flow.
    #[error("OIDC callback state does not match")]
    StateMismatch,
    /// The pending authorization has expired.
    #[error("OIDC authorization has expired")]
    Expired,
    /// Account linking was not initiated by a recent authenticated user.
    #[error("OIDC account linking requires recent authentication")]
    LinkProofRequired,
    /// The provider metadata cannot support authorization-code exchange.
    #[error("OIDC provider metadata was rejected")]
    ProviderMetadataRejected,
    /// The authorization code exchange failed.
    #[error("OIDC authorization code exchange failed")]
    TokenExchangeFailed,
    /// The provider token response omitted an ID token.
    #[error("OIDC ID token is required")]
    MissingIdToken,
    /// The ID token failed signature, issuer, audience, expiry, nonce, or subject validation.
    #[error("OIDC ID token was rejected")]
    IdTokenRejected,
    /// A bounded provider metadata/JWKS refresh failed.
    #[error("OIDC provider key refresh failed")]
    ProviderRefreshUnavailable,
    /// Synchronized protocol state was unavailable.
    #[error("OIDC internal state is unavailable")]
    InternalState,
}

impl OidcFlowError {
    const fn label(self) -> &'static str {
        match self {
            Self::UnknownProvider => "unknown_provider",
            Self::MalformedCallback => "malformed_callback",
            Self::ContextMismatch => "context_mismatch",
            Self::StateMismatch => "state_mismatch",
            Self::Expired => "expired",
            Self::LinkProofRequired => "link_proof_required",
            Self::ProviderMetadataRejected => "provider_metadata_rejected",
            Self::TokenExchangeFailed => "token_exchange_failed",
            Self::MissingIdToken => "missing_id_token",
            Self::IdTokenRejected => "id_token_rejected",
            Self::ProviderRefreshUnavailable => "provider_refresh_unavailable",
            Self::InternalState => "internal_state",
        }
    }
}
