use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    str::FromStr as _,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use metrics::counter;
use rsk_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use rsk_config::DeploymentEnvironment;
use rsk_outbound_http::{Method, OutboundHttpClients, PolicyClass, Url};
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};

use crate::{JwtConfig, JwtConfigError, JwtIssuerConfig};

#[derive(Clone)]
struct CachedKey {
    algorithm: Algorithm,
    key: DecodingKey,
}

struct KeyCache {
    loaded_at: Instant,
    keys: BTreeMap<String, CachedKey>,
}

struct RefreshState {
    last_forced_attempt: Option<Instant>,
    last_failed_attempt: Option<Instant>,
}

struct IssuerVerifier {
    issuer: String,
    jwks_url: Url,
    allowed_algorithms: HashSet<Algorithm>,
    cache_ttl: Duration,
    min_refresh_interval: Duration,
    max_jwks_bytes: usize,
    max_keys: usize,
    max_kid_bytes: usize,
    http: OutboundHttpClients,
    cache: RwLock<Option<KeyCache>>,
    refresh: Mutex<RefreshState>,
}

impl IssuerVerifier {
    async fn ensure_fresh(&self, force: bool) -> Result<bool, JwtVerifyError> {
        if !force && self.cache_is_fresh().await {
            return Ok(false);
        }
        let mut refresh = self.refresh.lock().await;
        if !force && self.cache_is_fresh().await {
            return Ok(false);
        }
        let now = Instant::now();
        if refresh
            .last_failed_attempt
            .is_some_and(|attempt| now.duration_since(attempt) < self.min_refresh_interval)
        {
            return self.require_fresh_cache().await;
        }
        if force
            && refresh
                .last_forced_attempt
                .is_some_and(|attempt| now.duration_since(attempt) < self.min_refresh_interval)
        {
            return self.require_fresh_cache().await;
        }
        let result = self.fetch_keys().await;
        let completed_at = Instant::now();
        if force {
            refresh.last_forced_attempt = Some(completed_at);
        }
        refresh.last_failed_attempt = result.as_ref().err().map(|_| completed_at);
        counter!(
            "rsk_auth_jwt_jwks_refresh_total",
            "result" => if result.is_ok() { "success" } else { "failure" }
        )
        .increment(1);
        let keys = result?;
        *self.cache.write().await = Some(KeyCache {
            loaded_at: completed_at,
            keys,
        });
        Ok(true)
    }

    async fn require_fresh_cache(&self) -> Result<bool, JwtVerifyError> {
        if self.cache_is_fresh().await {
            Ok(false)
        } else {
            Err(JwtVerifyError::JwksUnavailable)
        }
    }

    async fn cache_is_fresh(&self) -> bool {
        self.cache
            .read()
            .await
            .as_ref()
            .is_some_and(|cache| cache.loaded_at.elapsed() < self.cache_ttl)
    }

    async fn cached_key(&self, kid: &str, algorithm: Algorithm) -> Option<DecodingKey> {
        self.cache
            .read()
            .await
            .as_ref()
            .filter(|cache| cache.loaded_at.elapsed() < self.cache_ttl)
            .and_then(|cache| cache.keys.get(kid))
            .filter(|key| key.algorithm == algorithm)
            .map(|key| key.key.clone())
    }

    async fn fetch_keys(&self) -> Result<BTreeMap<String, CachedKey>, JwtVerifyError> {
        let request = self
            .http
            .request(PolicyClass::NoRedirect, Method::GET, self.jwks_url.clone())
            .header("accept", "application/json")
            .build()
            .map_err(|_| JwtVerifyError::JwksUnavailable)?;
        let response = self
            .http
            .execute_bounded_with_limit(request, self.max_jwks_bytes)
            .await
            .map_err(|_| JwtVerifyError::JwksUnavailable)?;
        if !response.status().is_success() {
            return Err(JwtVerifyError::JwksUnavailable);
        }
        let set: JwkSet =
            serde_json::from_slice(response.body()).map_err(|_| JwtVerifyError::InvalidJwks)?;
        validate_jwks(
            set,
            &self.allowed_algorithms,
            self.max_keys,
            self.max_kid_bytes,
        )
    }
}

/// Bounded resource-server verifier backed by explicit JWKS trust anchors.
#[derive(Clone)]
pub struct JwtVerifier {
    issuers: Arc<[Arc<IssuerVerifier>]>,
    audiences: Arc<[String]>,
    allowed_algorithms: Arc<[Algorithm]>,
    token_types: Arc<[String]>,
    clock_skew_seconds: u64,
    max_token_lifetime_seconds: u64,
    max_token_bytes: usize,
    max_kid_bytes: usize,
}

impl fmt::Debug for JwtVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtVerifier")
            .field("issuer_count", &self.issuers.len())
            .field("audience_count", &self.audiences.len())
            .field("algorithm_count", &self.allowed_algorithms.len())
            .field("token_type_count", &self.token_types.len())
            .finish_non_exhaustive()
    }
}

impl JwtVerifier {
    /// Validates configuration and primes every issuer's bounded JWKS cache.
    ///
    /// # Errors
    ///
    /// Returns a value-free build failure when configuration or an initial JWKS is invalid.
    pub async fn initialize(
        config: &JwtConfig,
        deployment: DeploymentEnvironment,
        http: OutboundHttpClients,
    ) -> Result<Self, JwtBuildError> {
        config
            .validate_for(deployment)
            .map_err(JwtBuildError::Config)?;
        if !config.enabled {
            return Err(JwtBuildError::Disabled);
        }
        let allowed_algorithms = config
            .algorithms
            .iter()
            .copied()
            .map(Algorithm::from)
            .collect::<Vec<_>>();
        let allowed_set = allowed_algorithms.iter().copied().collect::<HashSet<_>>();
        let mut issuers = Vec::with_capacity(config.issuers.len());
        for issuer in &config.issuers {
            let state = Arc::new(build_issuer(config, issuer, &allowed_set, http.clone())?);
            state
                .ensure_fresh(false)
                .await
                .map_err(|_| JwtBuildError::InitialJwks)?;
            issuers.push(state);
        }
        Ok(Self {
            issuers: issuers.into(),
            audiences: config.audiences.clone().into(),
            allowed_algorithms: allowed_algorithms.into(),
            token_types: config.token_types.clone().into(),
            clock_skew_seconds: config.clock_skew.as_secs(),
            max_token_lifetime_seconds: config.max_token_lifetime.as_secs(),
            max_token_bytes: config.max_token_bytes,
            max_kid_bytes: config.max_kid_bytes,
        })
    }

    /// Verifies a bearer access token and maps it to the canonical principal.
    ///
    /// # Errors
    ///
    /// Returns a stable value-free classification for every rejected token.
    pub async fn verify(&self, token: &str) -> Result<Principal, JwtVerifyError> {
        let result = self.verify_inner(token).await;
        counter!(
            "rsk_auth_jwt_verifications_total",
            "result" => result.as_ref().map_or_else(|error| (*error).label(), |_| "success")
        )
        .increment(1);
        result
    }

    async fn verify_inner(&self, token: &str) -> Result<Principal, JwtVerifyError> {
        if token.len() > self.max_token_bytes
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(JwtVerifyError::MalformedToken);
        }
        let header = decode_header(token).map_err(|_| JwtVerifyError::MalformedToken)?;
        if !self.allowed_algorithms.contains(&header.alg) {
            return Err(JwtVerifyError::AlgorithmRejected);
        }
        let kid = header.kid.ok_or(JwtVerifyError::KeyIdRejected)?;
        if kid.is_empty() || kid.len() > self.max_kid_bytes || kid.chars().any(char::is_control) {
            return Err(JwtVerifyError::KeyIdRejected);
        }
        let token_type = header.typ.ok_or(JwtVerifyError::TokenClassRejected)?;
        if !self
            .token_types
            .iter()
            .any(|expected| expected == &token_type)
        {
            return Err(JwtVerifyError::TokenClassRejected);
        }

        let (principal, refresh_mask) = self.try_verify(token, &kid, header.alg, None).await?;
        if let Some(principal) = principal {
            return Ok(principal);
        }
        if refresh_mask.iter().any(|refresh| *refresh)
            && let Some(principal) = self
                .try_verify(token, &kid, header.alg, Some(&refresh_mask))
                .await?
                .0
        {
            return Ok(principal);
        }
        Err(JwtVerifyError::TokenRejected)
    }

    async fn try_verify(
        &self,
        token: &str,
        kid: &str,
        algorithm: Algorithm,
        refresh_mask: Option<&[bool]>,
    ) -> Result<(Option<Principal>, Vec<bool>), JwtVerifyError> {
        let force_refresh = refresh_mask.is_some();
        let mut refresh_failed = false;
        let mut unknown_keys = Vec::with_capacity(self.issuers.len());
        for (index, issuer) in self.issuers.iter().enumerate() {
            if refresh_mask.is_some_and(|mask| !mask[index]) {
                unknown_keys.push(false);
                continue;
            }
            let Ok(refreshed) = issuer.ensure_fresh(force_refresh).await else {
                refresh_failed = true;
                unknown_keys.push(true);
                continue;
            };
            let Some(key) = issuer.cached_key(kid, algorithm).await else {
                unknown_keys.push(!refreshed);
                continue;
            };
            unknown_keys.push(false);
            if let Ok(principal) = self.decode_for_issuer(token, algorithm, &key, &issuer.issuer) {
                return Ok((Some(principal), unknown_keys));
            }
        }
        if refresh_failed && force_refresh {
            return Err(JwtVerifyError::JwksUnavailable);
        }
        Ok((None, unknown_keys))
    }

    fn decode_for_issuer(
        &self,
        token: &str,
        algorithm: Algorithm,
        key: &DecodingKey,
        issuer: &str,
    ) -> Result<Principal, JwtVerifyError> {
        let mut validation = Validation::new(algorithm);
        validation.algorithms = vec![algorithm];
        validation.leeway = self.clock_skew_seconds;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.set_issuer(&[issuer]);
        validation.set_audience(self.audiences.as_ref());
        let token = decode::<AccessTokenClaims>(token, key, &validation)
            .map_err(|_| JwtVerifyError::ClaimsRejected)?;
        claims_to_principal(
            token.claims,
            self.clock_skew_seconds,
            self.max_token_lifetime_seconds,
        )
    }
}

fn build_issuer(
    config: &JwtConfig,
    issuer: &JwtIssuerConfig,
    allowed_algorithms: &HashSet<Algorithm>,
    http: OutboundHttpClients,
) -> Result<IssuerVerifier, JwtBuildError> {
    Ok(IssuerVerifier {
        issuer: issuer.issuer.clone(),
        jwks_url: Url::parse(&issuer.jwks_url).map_err(|_| JwtBuildError::ConfigInvariant)?,
        allowed_algorithms: allowed_algorithms.clone(),
        cache_ttl: config.cache_ttl,
        min_refresh_interval: config.min_refresh_interval,
        max_jwks_bytes: config.max_jwks_bytes,
        max_keys: config.max_keys_per_issuer,
        max_kid_bytes: config.max_kid_bytes,
        http,
        cache: RwLock::new(None),
        refresh: Mutex::new(RefreshState {
            last_forced_attempt: None,
            last_failed_attempt: None,
        }),
    })
}

fn validate_jwks(
    set: JwkSet,
    allowed_algorithms: &HashSet<Algorithm>,
    max_keys: usize,
    max_kid_bytes: usize,
) -> Result<BTreeMap<String, CachedKey>, JwtVerifyError> {
    if set.keys.is_empty() || set.keys.len() > max_keys {
        return Err(JwtVerifyError::InvalidJwks);
    }
    let mut keys = BTreeMap::new();
    for jwk in set.keys {
        let kid = valid_jwk_kid(&jwk, max_kid_bytes)?;
        if !valid_jwk_usage(&jwk) {
            return Err(JwtVerifyError::InvalidJwks);
        }
        let algorithm = jwk
            .common
            .key_algorithm
            .and_then(|algorithm| Algorithm::try_from(algorithm).ok())
            .filter(|algorithm| allowed_algorithms.contains(algorithm))
            .ok_or(JwtVerifyError::InvalidJwks)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| JwtVerifyError::InvalidJwks)?;
        if key.family() != algorithm.family() {
            return Err(JwtVerifyError::InvalidJwks);
        }
        if keys.insert(kid, CachedKey { algorithm, key }).is_some() {
            return Err(JwtVerifyError::InvalidJwks);
        }
    }
    Ok(keys)
}

fn valid_jwk_kid(jwk: &Jwk, max_kid_bytes: usize) -> Result<String, JwtVerifyError> {
    let kid = jwk
        .common
        .key_id
        .as_ref()
        .filter(|kid| {
            !kid.is_empty() && kid.len() <= max_kid_bytes && !kid.chars().any(char::is_control)
        })
        .ok_or(JwtVerifyError::InvalidJwks)?;
    Ok(kid.clone())
}

fn valid_jwk_usage(jwk: &Jwk) -> bool {
    let use_valid = jwk
        .common
        .public_key_use
        .as_ref()
        .is_none_or(|value| value == &PublicKeyUse::Signature);
    let operations_valid = jwk.common.key_operations.as_ref().is_none_or(|operations| {
        !operations.is_empty()
            && operations
                .iter()
                .all(|operation| operation == &KeyOperations::Verify)
    });
    use_valid && operations_valid
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct AccessTokenClaims {
    sub: String,
    #[serde(rename = "iss")]
    _issuer: String,
    aud: AudienceClaim,
    exp: u64,
    nbf: u64,
    iat: u64,
    kind: PrincipalKind,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    assurance: Option<AssuranceLevel>,
}

fn claims_to_principal(
    claims: AccessTokenClaims,
    clock_skew_seconds: u64,
    max_token_lifetime_seconds: u64,
) -> Result<Principal, JwtVerifyError> {
    let AccessTokenClaims {
        sub,
        _issuer: _,
        aud,
        exp,
        nbf,
        iat,
        kind,
        tenant_id,
        scope,
        assurance,
    } = claims;
    consume_audience(aud);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JwtVerifyError::ClaimsRejected)?
        .as_secs();
    if exp <= iat
        || nbf > exp
        || exp - iat > max_token_lifetime_seconds
        || iat > now.saturating_add(clock_skew_seconds)
    {
        return Err(JwtVerifyError::ClaimsRejected);
    }
    let subject_id = SubjectId::from_str(&sub).map_err(|_| JwtVerifyError::ClaimsRejected)?;
    let tenant_id = tenant_id
        .map(|value| TenantId::from_str(&value))
        .transpose()
        .map_err(|_| JwtVerifyError::ClaimsRejected)?;
    let scopes = scope
        .as_deref()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(Scope::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| JwtVerifyError::ClaimsRejected)?;
    let authenticated_at = i64::try_from(iat)
        .ok()
        .and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok())
        .ok_or(JwtVerifyError::ClaimsRejected)?;
    Principal::new(
        subject_id,
        kind,
        tenant_id,
        AuthMethod::Jwt,
        authenticated_at,
        assurance.unwrap_or(AssuranceLevel::Aal1),
        scopes,
    )
    .map_err(|_| JwtVerifyError::ClaimsRejected)
}

fn consume_audience(audience: AudienceClaim) {
    match audience {
        AudienceClaim::One(value) => drop(value),
        AudienceClaim::Many(values) => drop(values),
    }
}

/// Stable verifier construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JwtBuildError {
    /// The capability was disabled.
    #[error("JWT verification is disabled")]
    Disabled,
    /// Configuration validation failed.
    #[error("JWT verification configuration is invalid")]
    Config(JwtConfigError),
    /// Validated configuration could not be restored internally.
    #[error("JWT verifier configuration invariant failed")]
    ConfigInvariant,
    /// An issuer's initial JWKS could not be fetched or validated.
    #[error("JWT initial JWKS is unavailable")]
    InitialJwks,
}

/// Stable bearer verification failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JwtVerifyError {
    /// Token syntax or size was invalid.
    #[error("bearer token is malformed")]
    MalformedToken,
    /// The header algorithm was not explicitly allowed.
    #[error("bearer token algorithm is rejected")]
    AlgorithmRejected,
    /// The key identifier was absent or outside supported bounds.
    #[error("bearer token key identifier is rejected")]
    KeyIdRejected,
    /// The token class was not an allowed access-token class.
    #[error("bearer token class is rejected")]
    TokenClassRejected,
    /// Claims were missing, malformed, inconsistent, or outside policy.
    #[error("bearer token claims are rejected")]
    ClaimsRejected,
    /// No trusted issuer and key accepted the token.
    #[error("bearer token is rejected")]
    TokenRejected,
    /// A bounded JWKS request failed.
    #[error("JWT key set is unavailable")]
    JwksUnavailable,
    /// A fetched JWKS violated key or resource policy.
    #[error("JWT key set is invalid")]
    InvalidJwks,
}

impl JwtVerifyError {
    const fn label(self) -> &'static str {
        match self {
            Self::MalformedToken => "malformed",
            Self::AlgorithmRejected => "algorithm",
            Self::KeyIdRejected => "kid",
            Self::TokenClassRejected => "token_class",
            Self::ClaimsRejected => "claims",
            Self::TokenRejected => "rejected",
            Self::JwksUnavailable => "jwks_unavailable",
            Self::InvalidJwks => "jwks_invalid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_outbound_http::OutboundHttpConfig;

    #[tokio::test]
    async fn refresh_backoff_never_exposes_stale_keys() -> Result<(), Box<dyn std::error::Error>> {
        let mut keys = BTreeMap::new();
        keys.insert(
            "old".to_owned(),
            CachedKey {
                algorithm: Algorithm::RS256,
                key: DecodingKey::from_secret(b"test-only"),
            },
        );
        let now = Instant::now();
        let loaded_at = now
            .checked_sub(Duration::from_secs(31))
            .ok_or(JwtVerifyError::ClaimsRejected)?;
        let issuer = IssuerVerifier {
            issuer: "https://issuer.example.test".to_owned(),
            jwks_url: Url::parse("https://issuer.example.test/jwks")?,
            allowed_algorithms: HashSet::from([Algorithm::RS256]),
            cache_ttl: Duration::from_secs(30),
            min_refresh_interval: Duration::from_secs(30),
            max_jwks_bytes: 1_024,
            max_keys: 1,
            max_kid_bytes: 16,
            http: OutboundHttpClients::new(&OutboundHttpConfig::default())?,
            cache: RwLock::new(Some(KeyCache { loaded_at, keys })),
            refresh: Mutex::new(RefreshState {
                last_forced_attempt: Some(now),
                last_failed_attempt: Some(now),
            }),
        };

        assert_eq!(
            issuer.ensure_fresh(false).await,
            Err(JwtVerifyError::JwksUnavailable)
        );
        assert!(issuer.cached_key("old", Algorithm::RS256).await.is_none());
        Ok(())
    }
}
