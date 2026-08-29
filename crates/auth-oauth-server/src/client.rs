//! SSRF-safe Client ID Metadata Document resolution and valid-document caching.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

use omnius_outbound_http::{
    BoundedResponse, Method, OutboundHttpClients, OutboundHttpError, PolicyClass, Url,
};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc2822};
use tokio::sync::Semaphore;

use crate::{
    Clock,
    config::ValidatedAuthorizationServerConfig,
    types::{ClientId, ClientMetadata, TokenEndpointAuthMethod},
};

const MAX_CONCURRENT_FETCHES: usize = 64;
const MAX_CACHE_HEADER_BYTES: usize = 2_048;
const MAX_ETAG_BYTES: usize = 512;
const MAX_HTTP_DATE_BYTES: usize = 128;

/// Value-free Client ID Metadata Document resolution failure.
///
/// No variant retains a URL, address, response body, metadata value, or credential.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClientMetadataResolverError {
    /// The client identifier is not a compliant Client Identifier URL.
    #[error("client identifier URL is invalid")]
    InvalidClientIdentifier,
    /// URL or resolved-address policy rejected a fetch destination.
    #[error("client metadata destination was rejected")]
    DestinationRejected,
    /// DNS resolution failed or returned no complete public answer set.
    #[error("client metadata destination resolution failed")]
    ResolutionFailed,
    /// The request timed out.
    #[error("client metadata request timed out")]
    Timeout,
    /// The remote request or response stream failed.
    #[error("client metadata transport failed")]
    TransportFailed,
    /// A redirect response or changed effective URL was rejected.
    #[error("client metadata redirect was rejected")]
    RedirectRejected,
    /// The response did not have the required success status.
    #[error("client metadata response status is invalid")]
    InvalidStatus,
    /// The response was not JSON media.
    #[error("client metadata response content type is invalid")]
    InvalidContentType,
    /// The decoded response exceeded the configured streaming ceiling.
    #[error("client metadata response is too large")]
    ResponseTooLarge,
    /// The document was malformed or violated client metadata policy.
    #[error("client metadata document is invalid")]
    InvalidDocument,
    /// Shared-secret or private key material was present.
    #[error("client metadata credential material is forbidden")]
    ForbiddenCredentialMaterial,
    /// The configured concurrency bound is invalid or unavailable.
    #[error("client metadata concurrency is unavailable")]
    ConcurrencyUnavailable,
    /// Valid-document cache state could not be accessed.
    #[error("client metadata cache is unavailable")]
    CacheUnavailable,
}

/// Successful HTTP cache validators retained with one validated document.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ClientMetadataCacheValidators {
    etag: Option<String>,
    last_modified: Option<String>,
}

impl ClientMetadataCacheValidators {
    /// Entity tag sent on conditional revalidation, when supplied by the origin.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Last-Modified value sent on conditional revalidation, when supplied by the origin.
    #[must_use]
    pub fn last_modified(&self) -> Option<&str> {
        self.last_modified.as_deref()
    }
}

impl fmt::Debug for ClientMetadataCacheValidators {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientMetadataCacheValidators")
            .field("etag_present", &self.etag.is_some())
            .field("last_modified_present", &self.last_modified.is_some())
            .finish()
    }
}

/// One validated Client ID Metadata Document resolution.
#[derive(Clone)]
pub struct ResolvedClientMetadata(Arc<ResolvedClientMetadataInner>);

struct ResolvedClientMetadataInner {
    metadata: Arc<ClientMetadata>,
    document: Arc<Vec<u8>>,
    validators: ClientMetadataCacheValidators,
    expires_at: OffsetDateTime,
    cacheable: bool,
}

impl ResolvedClientMetadata {
    /// Validated client metadata shared with pre-registration and DCR paths.
    #[must_use]
    pub fn metadata(&self) -> &ClientMetadata {
        self.0.metadata.as_ref()
    }

    /// Original validated document bytes for durable valid-document caching.
    #[must_use]
    pub fn document_bytes(&self) -> &[u8] {
        self.0.document.as_slice()
    }

    /// Successful response validators, if the origin supplied them.
    #[must_use]
    pub fn validators(&self) -> &ClientMetadataCacheValidators {
        &self.0.validators
    }

    /// Exclusive in-memory freshness deadline, never later than the configured TTL.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.0.expires_at
    }

    /// Whether HTTP policy permits retaining this valid response.
    #[must_use]
    pub fn is_cacheable(&self) -> bool {
        self.0.cacheable
    }
}

impl fmt::Debug for ResolvedClientMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedClientMetadata")
            .field("metadata", &"[REDACTED]")
            .field("document", &"[REDACTED]")
            .field("validators", &self.0.validators)
            .field("expires_at", &self.0.expires_at)
            .field("cacheable", &self.0.cacheable)
            .finish()
    }
}

/// Bounded, transport-neutral CIMD resolver backed by the shared outbound HTTP policy.
#[derive(Clone)]
pub struct ClientMetadataResolver {
    inner: Arc<ClientMetadataResolverInner>,
}

struct ClientMetadataResolverInner {
    transport: Arc<dyn MetadataTransport>,
    clock: Arc<dyn Clock>,
    cache_ttl: Duration,
    max_document_bytes: usize,
    permits: Semaphore,
    cache: RwLock<HashMap<ClientId, CacheEntry>>,
}

impl ClientMetadataResolver {
    /// Builds a resolver from validated provider limits and the shared outbound client.
    ///
    /// `max_concurrent_fetches` must be between one and 64. Every metadata and referenced JWKS
    /// request uses the caller-provided [`OutboundHttpClients`] approval and connect-time DNS
    /// policy with [`PolicyClass::NoRedirect`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientMetadataResolverError::ConcurrencyUnavailable`] for an invalid bound.
    pub fn new(
        http: Arc<OutboundHttpClients>,
        clock: Arc<dyn Clock>,
        config: &ValidatedAuthorizationServerConfig,
        max_concurrent_fetches: usize,
    ) -> Result<Self, ClientMetadataResolverError> {
        Self::from_transport(
            Arc::new(OutboundMetadataTransport { http }),
            clock,
            config.client_metadata_cache_ttl(),
            config.max_client_metadata_bytes(),
            max_concurrent_fetches,
        )
    }

    fn from_transport(
        transport: Arc<dyn MetadataTransport>,
        clock: Arc<dyn Clock>,
        cache_ttl: Duration,
        max_document_bytes: usize,
        max_concurrent_fetches: usize,
    ) -> Result<Self, ClientMetadataResolverError> {
        if !(1..=MAX_CONCURRENT_FETCHES).contains(&max_concurrent_fetches)
            || cache_ttl.is_zero()
            || max_document_bytes == 0
        {
            return Err(ClientMetadataResolverError::ConcurrencyUnavailable);
        }
        Ok(Self {
            inner: Arc::new(ClientMetadataResolverInner {
                transport,
                clock,
                cache_ttl,
                max_document_bytes,
                permits: Semaphore::new(max_concurrent_fetches),
                cache: RwLock::new(HashMap::new()),
            }),
        })
    }

    /// Resolves and validates one HTTPS URL-form client identifier.
    ///
    /// Fresh valid documents are served from the in-memory cache. Expired valid documents are
    /// conditionally revalidated. Error responses, transport failures, and invalid or malformed
    /// documents are never inserted or served as cache entries.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ClientMetadataResolverError`] for URL/DNS/connect policy, response,
    /// body-limit, JSON, credential-material, metadata, concurrency, or cache failure.
    pub async fn resolve(
        &self,
        client_id: &ClientId,
    ) -> Result<ResolvedClientMetadata, ClientMetadataResolverError> {
        let url = parse_client_identifier_url(client_id)?;
        let now = self.inner.clock.now_utc().to_offset(UtcOffset::UTC);
        if let Some(fresh) = self.fresh_cached(client_id, now)? {
            return Ok(fresh);
        }

        let _permit = self
            .inner
            .permits
            .acquire()
            .await
            .map_err(|_| ClientMetadataResolverError::ConcurrencyUnavailable)?;

        let now = self.inner.clock.now_utc().to_offset(UtcOffset::UTC);
        if let Some(fresh) = self.fresh_cached(client_id, now)? {
            return Ok(fresh);
        }
        let stale = self.cached(client_id)?;
        let request = FetchRequest {
            url: url.clone(),
            etag: stale
                .as_ref()
                .and_then(|entry| entry.resolved.validators().etag()),
            last_modified: stale
                .as_ref()
                .and_then(|entry| entry.resolved.validators().last_modified()),
            max_bytes: self.inner.max_document_bytes,
        };
        let response = self.inner.transport.fetch(request).await?;
        if response.effective_url != url {
            self.remove_cached(client_id)?;
            return Err(ClientMetadataResolverError::RedirectRejected);
        }

        if response.status == 304 {
            return self.revalidate_not_modified(client_id, stale, response, now);
        }
        if response.status != 200 {
            self.remove_cached(client_id)?;
            return Err(if (300..400).contains(&response.status) {
                ClientMetadataResolverError::RedirectRejected
            } else {
                ClientMetadataResolverError::InvalidStatus
            });
        }
        if !is_json_media_type(response.content_type.as_deref()) {
            self.remove_cached(client_id)?;
            return Err(ClientMetadataResolverError::InvalidContentType);
        }
        if response.body.is_empty() || response.body.len() > self.inner.max_document_bytes {
            self.remove_cached(client_id)?;
            return Err(if response.body.len() > self.inner.max_document_bytes {
                ClientMetadataResolverError::ResponseTooLarge
            } else {
                ClientMetadataResolverError::InvalidDocument
            });
        }

        let policy = cache_policy(&response, now, self.inner.cache_ttl, None);
        let validators = validators_from(&response, None);
        let document = Arc::new(response.body);
        let metadata = match self.validate_document(client_id, document.as_slice()).await {
            Ok(metadata) => metadata,
            Err(error) => {
                self.remove_cached(client_id)?;
                return Err(error);
            }
        };
        let resolved = resolved_metadata(metadata, document, validators, now, policy);
        self.store_valid(client_id, &resolved, policy)?;
        Ok(resolved)
    }

    fn cached(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<CacheEntry>, ClientMetadataResolverError> {
        self.inner
            .cache
            .read()
            .map_err(|_| ClientMetadataResolverError::CacheUnavailable)
            .map(|cache| cache.get(client_id).cloned())
    }

    fn fresh_cached(
        &self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<ResolvedClientMetadata>, ClientMetadataResolverError> {
        Ok(self
            .cached(client_id)?
            .filter(|entry| now < entry.resolved.expires_at())
            .map(|entry| entry.resolved))
    }

    fn remove_cached(&self, client_id: &ClientId) -> Result<(), ClientMetadataResolverError> {
        self.inner
            .cache
            .write()
            .map_err(|_| ClientMetadataResolverError::CacheUnavailable)?
            .remove(client_id);
        Ok(())
    }

    fn store_valid(
        &self,
        client_id: &ClientId,
        resolved: &ResolvedClientMetadata,
        policy: CachePolicy,
    ) -> Result<(), ClientMetadataResolverError> {
        let mut cache = self
            .inner
            .cache
            .write()
            .map_err(|_| ClientMetadataResolverError::CacheUnavailable)?;
        if policy.cacheable {
            cache.insert(
                client_id.clone(),
                CacheEntry {
                    resolved: resolved.clone(),
                    freshness_lifetime: policy.freshness_lifetime,
                },
            );
        } else {
            cache.remove(client_id);
        }
        Ok(())
    }

    fn revalidate_not_modified(
        &self,
        client_id: &ClientId,
        stale: Option<CacheEntry>,
        response: FetchResponse,
        now: OffsetDateTime,
    ) -> Result<ResolvedClientMetadata, ClientMetadataResolverError> {
        let Some(stale) = stale else {
            return Err(ClientMetadataResolverError::InvalidStatus);
        };
        if !response.body.is_empty() {
            self.remove_cached(client_id)?;
            return Err(ClientMetadataResolverError::InvalidStatus);
        }
        let fallback = CachePolicy {
            cacheable: true,
            freshness_lifetime: stale.freshness_lifetime,
        };
        let policy = cache_policy(&response, now, self.inner.cache_ttl, Some(fallback));
        let validators = validators_from(&response, Some(stale.resolved.validators()));
        let resolved = resolved_metadata(
            Arc::clone(&stale.resolved.0.metadata),
            Arc::clone(&stale.resolved.0.document),
            validators,
            now,
            policy,
        );
        self.store_valid(client_id, &resolved, policy)?;
        Ok(resolved)
    }

    async fn validate_document(
        &self,
        client_id: &ClientId,
        document: &[u8],
    ) -> Result<Arc<ClientMetadata>, ClientMetadataResolverError> {
        let mut value = serde_json::from_slice::<serde_json::Value>(document)
            .map_err(|_| ClientMetadataResolverError::InvalidDocument)?;
        let object = value
            .as_object_mut()
            .ok_or(ClientMetadataResolverError::InvalidDocument)?;
        reject_credential_material(object)?;

        let jwks_uri = object.remove("jwks_uri");
        let document_was_transformed = jwks_uri.is_some();
        if jwks_uri.is_some() && object.contains_key("jwks") {
            return Err(ClientMetadataResolverError::InvalidDocument);
        }
        if let Some(jwks_uri) = jwks_uri {
            let jwks_uri = jwks_uri
                .as_str()
                .ok_or(ClientMetadataResolverError::InvalidDocument)?;
            let jwks = self.fetch_public_jwks(jwks_uri).await?;
            object.insert("jwks".to_owned(), jwks);
        }
        if object
            .get("jwks")
            .is_some_and(contains_private_jwk_material)
        {
            return Err(ClientMetadataResolverError::ForbiddenCredentialMaterial);
        }

        let normalized = if document_was_transformed {
            Some(
                serde_json::to_vec(&value)
                    .map_err(|_| ClientMetadataResolverError::InvalidDocument)?,
            )
        } else {
            None
        };
        let metadata_document = normalized.as_deref().unwrap_or(document);
        if metadata_document.len() > self.inner.max_document_bytes {
            return Err(ClientMetadataResolverError::ResponseTooLarge);
        }
        let metadata = ClientMetadata::from_json(
            metadata_document,
            self.inner.max_document_bytes,
            Some(client_id),
        )
        .map_err(|_| ClientMetadataResolverError::InvalidDocument)?;
        if metadata.token_endpoint_auth_method() == TokenEndpointAuthMethod::ClientSecretBasic {
            return Err(ClientMetadataResolverError::ForbiddenCredentialMaterial);
        }
        Ok(Arc::new(metadata))
    }

    async fn fetch_public_jwks(
        &self,
        value: &str,
    ) -> Result<serde_json::Value, ClientMetadataResolverError> {
        let url = parse_referenced_https_url(value)?;
        let response = self
            .inner
            .transport
            .fetch(FetchRequest {
                url: url.clone(),
                etag: None,
                last_modified: None,
                max_bytes: self.inner.max_document_bytes,
            })
            .await?;
        if response.effective_url != url || (300..400).contains(&response.status) {
            return Err(ClientMetadataResolverError::RedirectRejected);
        }
        if response.status != 200 {
            return Err(ClientMetadataResolverError::InvalidStatus);
        }
        if !is_json_media_type(response.content_type.as_deref()) {
            return Err(ClientMetadataResolverError::InvalidContentType);
        }
        if response.body.is_empty() || response.body.len() > self.inner.max_document_bytes {
            return Err(if response.body.len() > self.inner.max_document_bytes {
                ClientMetadataResolverError::ResponseTooLarge
            } else {
                ClientMetadataResolverError::InvalidDocument
            });
        }
        let jwks = serde_json::from_slice::<serde_json::Value>(&response.body)
            .map_err(|_| ClientMetadataResolverError::InvalidDocument)?;
        if contains_private_jwk_material(&jwks) {
            return Err(ClientMetadataResolverError::ForbiddenCredentialMaterial);
        }
        Ok(jwks)
    }
}

impl fmt::Debug for ClientMetadataResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientMetadataResolver")
            .field("transport", &"[REDACTED]")
            .field("clock", &"[REDACTED]")
            .field("cache_ttl", &self.inner.cache_ttl)
            .field("max_document_bytes", &self.inner.max_document_bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct CacheEntry {
    resolved: ResolvedClientMetadata,
    freshness_lifetime: Duration,
}

#[derive(Clone, Copy)]
struct CachePolicy {
    cacheable: bool,
    freshness_lifetime: Duration,
}

fn resolved_metadata(
    metadata: Arc<ClientMetadata>,
    document: Arc<Vec<u8>>,
    validators: ClientMetadataCacheValidators,
    now: OffsetDateTime,
    policy: CachePolicy,
) -> ResolvedClientMetadata {
    let expires_at = time::Duration::try_from(policy.freshness_lifetime)
        .ok()
        .and_then(|lifetime| now.checked_add(lifetime))
        .unwrap_or(now);
    ResolvedClientMetadata(Arc::new(ResolvedClientMetadataInner {
        metadata,
        document,
        validators,
        expires_at,
        cacheable: policy.cacheable,
    }))
}

fn cache_policy(
    response: &FetchResponse,
    now: OffsetDateTime,
    maximum: Duration,
    fallback: Option<CachePolicy>,
) -> CachePolicy {
    if response.cache_control.is_none() && response.expires.is_none() {
        return fallback.unwrap_or(CachePolicy {
            cacheable: true,
            freshness_lifetime: maximum,
        });
    }

    let mut no_store = false;
    let mut no_cache = false;
    let mut max_age = None;
    let mut malformed_max_age = false;
    if let Some(value) = response.cache_control.as_deref() {
        for directive in value.split(',') {
            let (name, argument) = directive
                .trim()
                .split_once('=')
                .map_or((directive.trim(), None), |(name, value)| {
                    (name.trim(), Some(value.trim().trim_matches('"')))
                });
            if name.eq_ignore_ascii_case("no-store") {
                no_store = true;
            } else if name.eq_ignore_ascii_case("no-cache") {
                no_cache = true;
            } else if name.eq_ignore_ascii_case("max-age") {
                match argument.and_then(|value| value.parse::<u64>().ok()) {
                    Some(seconds) => max_age = Some(Duration::from_secs(seconds)),
                    None => malformed_max_age = true,
                }
            }
        }
    }
    if no_store {
        return CachePolicy {
            cacheable: false,
            freshness_lifetime: Duration::ZERO,
        };
    }
    if no_cache || malformed_max_age {
        return CachePolicy {
            cacheable: true,
            freshness_lifetime: Duration::ZERO,
        };
    }

    let freshness = max_age.unwrap_or_else(|| {
        if response.expires.is_some() {
            expires_lifetime(response, now).unwrap_or_default()
        } else {
            maximum
        }
    });
    let age = response
        .age
        .as_deref()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_default();
    CachePolicy {
        cacheable: true,
        freshness_lifetime: freshness.saturating_sub(age).min(maximum),
    }
}

fn expires_lifetime(response: &FetchResponse, now: OffsetDateTime) -> Option<Duration> {
    let expires = response.expires.as_deref().and_then(parse_http_date)?;
    let base = response
        .date
        .as_deref()
        .and_then(parse_http_date)
        .unwrap_or(now);
    Duration::try_from(expires - base).ok()
}

fn parse_http_date(value: &str) -> Option<OffsetDateTime> {
    if value.len() > MAX_HTTP_DATE_BYTES {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc2822)
        .ok()
        .map(|value| value.to_offset(UtcOffset::UTC))
}

fn validators_from(
    response: &FetchResponse,
    previous: Option<&ClientMetadataCacheValidators>,
) -> ClientMetadataCacheValidators {
    ClientMetadataCacheValidators {
        etag: response
            .etag
            .clone()
            .or_else(|| previous.and_then(|value| value.etag.clone())),
        last_modified: response
            .last_modified
            .clone()
            .or_else(|| previous.and_then(|value| value.last_modified.clone())),
    }
}

fn parse_client_identifier_url(client_id: &ClientId) -> Result<Url, ClientMetadataResolverError> {
    let value = client_id.as_str();
    let url =
        Url::parse(value).map_err(|_| ClientMetadataResolverError::InvalidClientIdentifier)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || value.contains('\\')
    {
        return Err(ClientMetadataResolverError::InvalidClientIdentifier);
    }
    let path = raw_url_path(value).ok_or(ClientMetadataResolverError::InvalidClientIdentifier)?;
    if path.split('/').any(is_dot_path_segment) {
        return Err(ClientMetadataResolverError::InvalidClientIdentifier);
    }
    Ok(url)
}

fn parse_referenced_https_url(value: &str) -> Result<Url, ClientMetadataResolverError> {
    let url = Url::parse(value).map_err(|_| ClientMetadataResolverError::InvalidDocument)?;
    if value.len() > crate::types::MAX_URI_BYTES
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || value.contains('\\')
    {
        return Err(ClientMetadataResolverError::InvalidDocument);
    }
    Ok(url)
}

fn raw_url_path(value: &str) -> Option<&str> {
    let authority = value.split_once("://")?.1;
    let path_start = authority.find('/')?;
    let path_and_suffix = &authority[path_start..];
    let path_end = path_and_suffix
        .find(['?', '#'])
        .unwrap_or(path_and_suffix.len());
    Some(&path_and_suffix[..path_end])
}

fn is_dot_path_segment(segment: &str) -> bool {
    let mut dots = 0_usize;
    let bytes = segment.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] == b'.' {
            dots += 1;
            index += 1;
        } else if index + 2 < bytes.len()
            && bytes[index] == b'%'
            && bytes[index + 1] == b'2'
            && matches!(bytes[index + 2], b'e' | b'E')
        {
            dots += 1;
            index += 3;
        } else {
            return false;
        }
    }
    matches!(dots, 1 | 2)
}

fn reject_credential_material(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ClientMetadataResolverError> {
    if object.contains_key("client_secret") || object.contains_key("client_secret_expires_at") {
        return Err(ClientMetadataResolverError::ForbiddenCredentialMaterial);
    }
    if object
        .get("token_endpoint_auth_method")
        .and_then(serde_json::Value::as_str)
        .is_some_and(is_shared_secret_method)
    {
        return Err(ClientMetadataResolverError::ForbiddenCredentialMaterial);
    }
    if object
        .get("jwks")
        .is_some_and(contains_private_jwk_material)
    {
        return Err(ClientMetadataResolverError::ForbiddenCredentialMaterial);
    }
    Ok(())
}

fn is_shared_secret_method(value: &str) -> bool {
    matches!(
        value,
        "client_secret_basic" | "client_secret_post" | "client_secret_jwt"
    )
}

fn contains_private_jwk_material(value: &serde_json::Value) -> bool {
    let Some(keys) = value
        .as_object()
        .and_then(|object| object.get("keys"))
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    keys.iter().any(|key| {
        key.as_object().is_some_and(|key| {
            ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|member| key.contains_key(*member))
        })
    })
}

fn is_json_media_type(value: Option<&str>) -> bool {
    let Some(essence) = value
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    else {
        return false;
    };
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    kind.eq_ignore_ascii_case("application")
        && (subtype.eq_ignore_ascii_case("json")
            || subtype.len() > b"+json".len()
                && subtype.as_bytes()[subtype.len() - b"+json".len()..]
                    .eq_ignore_ascii_case(b"+json"))
}

struct FetchRequest<'a> {
    url: Url,
    etag: Option<&'a str>,
    last_modified: Option<&'a str>,
    max_bytes: usize,
}

struct FetchResponse {
    effective_url: Url,
    status: u16,
    content_type: Option<String>,
    cache_control: Option<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    expires: Option<String>,
    date: Option<String>,
    age: Option<String>,
    body: Vec<u8>,
}

type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FetchResponse, ClientMetadataResolverError>> + Send + 'a>>;

trait MetadataTransport: Send + Sync {
    fn fetch<'a>(&'a self, request: FetchRequest<'a>) -> FetchFuture<'a>;
}

struct OutboundMetadataTransport {
    http: Arc<OutboundHttpClients>,
}

impl MetadataTransport for OutboundMetadataTransport {
    fn fetch<'a>(&'a self, request: FetchRequest<'a>) -> FetchFuture<'a> {
        Box::pin(async move {
            let approved = self
                .http
                .approve(request.url)
                .await
                .map_err(map_outbound_error)?;
            let effective_url = approved.as_url().clone();
            let mut builder = self
                .http
                .request(PolicyClass::NoRedirect, Method::GET, &approved)
                .header("accept", "application/json");
            if let Some(etag) = request.etag {
                builder = builder.header("if-none-match", etag);
            }
            if let Some(last_modified) = request.last_modified {
                builder = builder.header("if-modified-since", last_modified);
            }
            let response = self
                .http
                .execute_bounded_with_limit(
                    builder.build().map_err(map_outbound_error)?,
                    request.max_bytes,
                )
                .await
                .map_err(map_outbound_error)?;
            fetch_response(effective_url, response)
        })
    }
}

fn fetch_response(
    effective_url: Url,
    response: BoundedResponse,
) -> Result<FetchResponse, ClientMetadataResolverError> {
    Ok(FetchResponse {
        effective_url,
        status: response.status().as_u16(),
        content_type: copy_header(&response, "content-type", MAX_CACHE_HEADER_BYTES)?,
        cache_control: copy_header(&response, "cache-control", MAX_CACHE_HEADER_BYTES)?,
        etag: copy_header(&response, "etag", MAX_ETAG_BYTES)?,
        last_modified: copy_header(&response, "last-modified", MAX_HTTP_DATE_BYTES)?,
        expires: copy_header(&response, "expires", MAX_HTTP_DATE_BYTES)?,
        date: copy_header(&response, "date", MAX_HTTP_DATE_BYTES)?,
        age: copy_header(&response, "age", MAX_HTTP_DATE_BYTES)?,
        body: response.into_body(),
    })
}

fn copy_header(
    response: &BoundedResponse,
    name: &str,
    max_bytes: usize,
) -> Result<Option<String>, ClientMetadataResolverError> {
    response
        .headers()
        .get(name)
        .map(|value| {
            value
                .to_str()
                .ok()
                .filter(|value| value.len() <= max_bytes)
                .map(str::to_owned)
                .ok_or(ClientMetadataResolverError::TransportFailed)
        })
        .transpose()
}

fn map_outbound_error(error: OutboundHttpError) -> ClientMetadataResolverError {
    match error {
        OutboundHttpError::DestinationRejected => ClientMetadataResolverError::DestinationRejected,
        OutboundHttpError::Resolution => ClientMetadataResolverError::ResolutionFailed,
        OutboundHttpError::Timeout => ClientMetadataResolverError::Timeout,
        OutboundHttpError::ResponseTooLarge | OutboundHttpError::InvalidResponseBodyLimit => {
            ClientMetadataResolverError::ResponseTooLarge
        }
        OutboundHttpError::RedirectRejected
        | OutboundHttpError::RedirectLimit
        | OutboundHttpError::RedirectLoop
        | OutboundHttpError::NonReplayableRedirect => ClientMetadataResolverError::RedirectRejected,
        OutboundHttpError::RequestBuild
        | OutboundHttpError::Transport
        | OutboundHttpError::ResponseBody => ClientMetadataResolverError::TransportFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
        sync::{
            Mutex,
            atomic::{AtomicI64, AtomicUsize, Ordering},
        },
    };

    use omnius_outbound_http::{
        OutboundHttpConfig, OutboundUrlPolicyConfig, ProxyPolicy, Resolver, ResolverError,
        ResolverFuture,
    };
    use serde_json::json;

    use super::*;

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(timestamp: i64) -> Self {
            Self(AtomicI64::new(timestamp))
        }

        fn advance(&self, seconds: i64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn now_utc(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(self.0.load(Ordering::Relaxed))
        }
    }

    struct FakeReply {
        status: u16,
        content_type: Option<String>,
        cache_control: Option<String>,
        etag: Option<String>,
        last_modified: Option<String>,
        body: Vec<u8>,
        effective_url: Option<Url>,
    }

    impl FakeReply {
        fn json(body: Vec<u8>) -> Self {
            Self {
                status: 200,
                content_type: Some("application/json".to_owned()),
                cache_control: Some("max-age=60".to_owned()),
                etag: Some("\"v1\"".to_owned()),
                last_modified: None,
                body,
                effective_url: None,
            }
        }
    }

    #[derive(Default)]
    struct FakeServer {
        replies: Mutex<VecDeque<Result<FakeReply, ClientMetadataResolverError>>>,
        calls: AtomicUsize,
        conditionals: Mutex<Vec<(Option<String>, Option<String>)>>,
    }

    impl FakeServer {
        fn new(replies: impl IntoIterator<Item = FakeReply>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().map(Ok).collect()),
                ..Self::default()
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl MetadataTransport for FakeServer {
        fn fetch<'a>(&'a self, request: FetchRequest<'a>) -> FetchFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.conditionals.lock().expect("conditionals lock").push((
                request.etag.map(str::to_owned),
                request.last_modified.map(str::to_owned),
            ));
            let reply = self
                .replies
                .lock()
                .expect("reply lock")
                .pop_front()
                .unwrap_or(Err(ClientMetadataResolverError::TransportFailed));
            Box::pin(async move {
                reply.map(|reply| FetchResponse {
                    effective_url: reply.effective_url.unwrap_or(request.url),
                    status: reply.status,
                    content_type: reply.content_type,
                    cache_control: reply.cache_control,
                    etag: reply.etag,
                    last_modified: reply.last_modified,
                    expires: None,
                    date: None,
                    age: None,
                    body: reply.body,
                })
            })
        }
    }

    fn metadata_document(client_id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "client_id": client_id,
            "client_name": "Example Client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"]
        }))
        .expect("metadata JSON")
    }

    fn client_id() -> ClientId {
        ClientId::parse("https://client.example/oauth/client.json").expect("client ID")
    }

    fn test_resolver(
        server: Arc<FakeServer>,
        clock: Arc<TestClock>,
        max_bytes: usize,
    ) -> ClientMetadataResolver {
        ClientMetadataResolver::from_transport(server, clock, Duration::from_secs(90), max_bytes, 2)
            .expect("resolver")
    }

    fn assert_resolution_error(
        result: Result<ResolvedClientMetadata, ClientMetadataResolverError>,
        expected: ClientMetadataResolverError,
    ) {
        assert_eq!(result.expect_err("resolution must fail"), expected);
    }

    #[tokio::test]
    async fn valid_document_is_cached_and_conditionally_revalidated() {
        let id = client_id();
        let first = FakeReply::json(metadata_document(id.as_str()));
        let not_modified = FakeReply {
            status: 304,
            content_type: None,
            cache_control: Some("max-age=600".to_owned()),
            etag: Some("\"v2\"".to_owned()),
            last_modified: None,
            body: Vec::new(),
            effective_url: None,
        };
        let server = Arc::new(FakeServer::new([first, not_modified]));
        let clock = Arc::new(TestClock::new(1_800_000_000));
        let resolver = test_resolver(Arc::clone(&server), Arc::clone(&clock), 4_096);

        let initial = resolver.resolve(&id).await.expect("initial resolution");
        let cached = resolver.resolve(&id).await.expect("fresh cache");
        assert_eq!(server.calls(), 1);
        assert_eq!(initial.document_bytes(), cached.document_bytes());

        clock.advance(61);
        let revalidated = resolver.resolve(&id).await.expect("revalidation");
        assert_eq!(server.calls(), 2);
        assert_eq!(revalidated.validators().etag(), Some("\"v2\""));
        assert_eq!(
            revalidated.expires_at(),
            clock.now_utc() + time::Duration::seconds(90)
        );
        assert_eq!(
            server
                .conditionals
                .lock()
                .expect("conditionals")
                .last()
                .cloned(),
            Some((Some("\"v1\"".to_owned()), None))
        );
    }

    #[tokio::test]
    async fn no_store_and_transient_failures_never_become_cache_entries() {
        let id = client_id();
        let mut no_store_one = FakeReply::json(metadata_document(id.as_str()));
        no_store_one.cache_control = Some("no-store".to_owned());
        let mut no_store_two = FakeReply::json(metadata_document(id.as_str()));
        no_store_two.cache_control = Some("no-store".to_owned());
        let server = Arc::new(FakeServer::new([no_store_one, no_store_two]));
        let resolver = test_resolver(
            Arc::clone(&server),
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        assert!(
            !resolver
                .resolve(&id)
                .await
                .expect("first response")
                .is_cacheable()
        );
        resolver.resolve(&id).await.expect("second response");
        assert_eq!(server.calls(), 2);

        let retry_server = Arc::new(FakeServer {
            replies: Mutex::new(VecDeque::from([
                Err(ClientMetadataResolverError::Timeout),
                Ok(FakeReply::json(metadata_document(id.as_str()))),
            ])),
            ..FakeServer::default()
        });
        let retry_resolver = test_resolver(
            Arc::clone(&retry_server),
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        assert_resolution_error(
            retry_resolver.resolve(&id).await,
            ClientMetadataResolverError::Timeout,
        );
        retry_resolver.resolve(&id).await.expect("transient retry");
        assert_eq!(retry_server.calls(), 2);
    }

    #[tokio::test]
    async fn invalid_client_identifier_urls_are_rejected_before_fetch() {
        let server = Arc::new(FakeServer::default());
        let resolver = test_resolver(
            Arc::clone(&server),
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        for value in [
            "http://client.example/client.json",
            "https://client.example",
            "https://user@client.example/client.json",
            "https://client.example/a/../client.json",
            "https://client.example/a/%2E%2e/client.json",
            "https://client.example/client.json#fragment",
        ] {
            let id = ClientId::parse(value).expect("bounded ID");
            assert_resolution_error(
                resolver.resolve(&id).await,
                ClientMetadataResolverError::InvalidClientIdentifier,
            );
        }
        assert_eq!(server.calls(), 0);
    }

    #[tokio::test]
    async fn redirect_status_and_changed_effective_url_are_rejected() {
        let id = client_id();
        let redirect = FakeReply {
            status: 302,
            content_type: Some("application/json".to_owned()),
            cache_control: None,
            etag: None,
            last_modified: None,
            body: Vec::new(),
            effective_url: None,
        };
        let changed = FakeReply {
            effective_url: Some(Url::parse("https://other.example/client.json").expect("URL")),
            ..FakeReply::json(metadata_document(id.as_str()))
        };
        let server = Arc::new(FakeServer::new([redirect, changed]));
        let resolver = test_resolver(server, Arc::new(TestClock::new(1_800_000_000)), 4_096);
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::RedirectRejected,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::RedirectRejected,
        );
    }

    #[tokio::test]
    async fn invalid_status_content_type_and_body_size_are_not_cached() {
        let id = client_id();
        let status = FakeReply {
            status: 503,
            ..FakeReply::json(Vec::new())
        };
        let content_type = FakeReply {
            content_type: Some("text/plain".to_owned()),
            ..FakeReply::json(metadata_document(id.as_str()))
        };
        let oversized = FakeReply::json(vec![b'x'; 65]);
        let success = FakeReply::json(metadata_document(id.as_str()));
        let server = Arc::new(FakeServer::new([status, content_type, oversized, success]));
        let resolver = test_resolver(
            Arc::clone(&server),
            Arc::new(TestClock::new(1_800_000_000)),
            64,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::InvalidStatus,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::InvalidContentType,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::ResponseTooLarge,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::ResponseTooLarge,
        );
        assert_eq!(server.calls(), 4);
    }

    #[tokio::test]
    async fn mismatched_client_id_secret_methods_and_private_keys_are_not_cached() {
        let id = client_id();
        let mismatched = metadata_document("https://other.example/client.json");
        let secret = serde_json::to_vec(&json!({
            "client_id": id.as_str(),
            "client_name": "Secret Client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
            "client_secret": "must-not-leak"
        }))
        .expect("secret JSON");
        let private = serde_json::to_vec(&json!({
            "client_id": id.as_str(),
            "client_name": "Private Key Client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{
                "kty": "RSA", "kid": "one", "n": "AQAB", "e": "AQAB", "d": "private"
            }]}
        }))
        .expect("private JSON");
        let server = Arc::new(FakeServer::new([
            FakeReply::json(mismatched),
            FakeReply::json(secret),
            FakeReply::json(private),
        ]));
        let resolver = test_resolver(
            Arc::clone(&server),
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::InvalidDocument,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::ForbiddenCredentialMaterial,
        );
        assert_resolution_error(
            resolver.resolve(&id).await,
            ClientMetadataResolverError::ForbiddenCredentialMaterial,
        );
        assert_eq!(server.calls(), 3);
    }

    #[tokio::test]
    async fn redirect_grant_response_jwks_and_auth_metadata_are_strictly_validated() {
        let id = client_id();
        let documents = [
            json!({
                "client_id": id.as_str(),
                "client_name": "Bad Redirect",
                "redirect_uris": ["http://public.example/callback"]
            }),
            json!({
                "client_id": id.as_str(),
                "client_name": "Bad Grant",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["refresh_token"]
            }),
            json!({
                "client_id": id.as_str(),
                "client_name": "Bad Response",
                "redirect_uris": ["https://client.example/callback"],
                "response_types": ["token"]
            }),
            json!({
                "client_id": id.as_str(),
                "client_name": "Bad JWKS",
                "redirect_uris": ["https://client.example/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [{"kty": "RSA", "kid": "one", "n": "AQAB"}]}
            }),
            json!({
                "client_id": id.as_str(),
                "client_name": "Bad Auth",
                "redirect_uris": ["https://client.example/callback"],
                "token_endpoint_auth_method": "tls_client_auth"
            }),
        ];
        let replies = documents
            .into_iter()
            .map(|document| FakeReply::json(serde_json::to_vec(&document).expect("metadata JSON")))
            .collect::<Vec<_>>();
        let server = Arc::new(FakeServer::new(replies));
        let resolver = test_resolver(
            Arc::clone(&server),
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        for _ in 0..5 {
            assert_resolution_error(
                resolver.resolve(&id).await,
                ClientMetadataResolverError::InvalidDocument,
            );
        }
        assert_eq!(server.calls(), 5);
    }

    #[tokio::test]
    async fn malformed_document_is_not_negative_cached() {
        let id = client_id();
        let server = Arc::new(FakeServer::new([
            FakeReply::json(b"not-json secret-body".to_vec()),
            FakeReply::json(metadata_document(id.as_str())),
        ]));
        let resolver = test_resolver(
            Arc::clone(&server),
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        let error = resolver.resolve(&id).await.expect_err("malformed document");
        assert_eq!(error, ClientMetadataResolverError::InvalidDocument);
        assert!(
            !format!("{error:?} {error}").contains("secret-body"),
            "errors must remain value-free"
        );
        resolver.resolve(&id).await.expect("retry succeeds");
        assert_eq!(server.calls(), 2);
    }

    #[tokio::test]
    async fn referenced_jwks_is_fetched_and_private_material_is_rejected() {
        let id = client_id();
        let document = serde_json::to_vec(&json!({
            "client_id": id.as_str(),
            "client_name": "Assertion Client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://client.example/oauth/jwks.json"
        }))
        .expect("metadata JSON");
        let public_jwks = serde_json::to_vec(&json!({
            "keys": [{"kty": "RSA", "kid": "one", "n": "AQAB", "e": "AQAB"}]
        }))
        .expect("JWKS JSON");
        let private_jwks = serde_json::to_vec(&json!({
            "keys": [{
                "kty": "RSA", "kid": "one", "n": "AQAB", "e": "AQAB", "d": "private"
            }]
        }))
        .expect("private JWKS JSON");
        let server = Arc::new(FakeServer::new([
            FakeReply::json(document),
            FakeReply::json(public_jwks),
        ]));
        let resolver = test_resolver(server, Arc::new(TestClock::new(1_800_000_000)), 4_096);
        let resolved = resolver.resolve(&id).await.expect("public JWKS");
        assert!(resolved.metadata().jwks().is_some());

        let second = ClientId::parse("https://client.example/oauth/second.json").expect("ID");
        let second_document = String::from_utf8(metadata_document(second.as_str()))
            .expect("UTF-8")
            .replace(
                "\"token_endpoint_auth_method\":\"none\"",
                "\"token_endpoint_auth_method\":\"private_key_jwt\",\"jwks_uri\":\"https://client.example/oauth/private.json\"",
            );
        let private_server = Arc::new(FakeServer::new([
            FakeReply::json(second_document.into_bytes()),
            FakeReply::json(private_jwks),
        ]));
        let private_resolver = test_resolver(
            private_server,
            Arc::new(TestClock::new(1_800_000_000)),
            4_096,
        );
        assert_resolution_error(
            private_resolver.resolve(&second).await,
            ClientMetadataResolverError::ForbiddenCredentialMaterial,
        );
    }

    #[derive(Clone)]
    struct FakeResolver {
        answers: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
    }

    impl FakeResolver {
        fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
            Self {
                answers: Arc::new(Mutex::new(answers.into_iter().collect())),
            }
        }
    }

    impl Resolver for FakeResolver {
        fn resolve<'a>(&'a self, _host: &'a str) -> ResolverFuture<'a> {
            let answer = self
                .answers
                .lock()
                .expect("resolver answers")
                .pop_front()
                .ok_or(ResolverError);
            Box::pin(async move { answer })
        }
    }

    fn outbound_config() -> OutboundHttpConfig {
        OutboundHttpConfig {
            connect_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(2),
            response_body_limit_bytes: 4_096,
            max_redirects: 1,
            proxy: ProxyPolicy::Disabled,
            user_agent: "omnius-cimd-test/1".to_owned(),
            url_policy: OutboundUrlPolicyConfig::default(),
        }
    }

    #[tokio::test]
    async fn special_use_dns_answers_are_rejected_by_shared_outbound_policy() {
        let http = Arc::new(
            OutboundHttpClients::with_resolver(
                &outbound_config(),
                Arc::new(FakeResolver::new([vec![IpAddr::V4(Ipv4Addr::new(
                    10, 0, 0, 1,
                ))]])),
            )
            .expect("outbound client"),
        );
        let resolver = ClientMetadataResolver::from_transport(
            Arc::new(OutboundMetadataTransport { http }),
            Arc::new(TestClock::new(1_800_000_000)),
            Duration::from_secs(60),
            4_096,
            1,
        )
        .expect("resolver");
        assert_resolution_error(
            resolver.resolve(&client_id()).await,
            ClientMetadataResolverError::DestinationRejected,
        );
    }

    #[tokio::test]
    async fn connect_time_dns_rebinding_is_rejected_by_shared_outbound_policy() {
        let http = Arc::new(
            OutboundHttpClients::with_resolver(
                &outbound_config(),
                Arc::new(FakeResolver::new([
                    vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                ])),
            )
            .expect("outbound client"),
        );
        let resolver = ClientMetadataResolver::from_transport(
            Arc::new(OutboundMetadataTransport { http }),
            Arc::new(TestClock::new(1_800_000_000)),
            Duration::from_secs(60),
            4_096,
            1,
        )
        .expect("resolver");
        assert_resolution_error(
            resolver.resolve(&client_id()).await,
            ClientMetadataResolverError::TransportFailed,
        );
    }

    #[test]
    fn debug_output_redacts_query_body_and_metadata() {
        let secret = "query-secret-never-log";
        let id = ClientId::parse(format!(
            "https://client.example/client.json?credential={secret}"
        ))
        .expect("client ID");
        let metadata = Arc::new(
            ClientMetadata::from_json(&metadata_document(id.as_str()), 4_096, Some(&id))
                .expect("metadata"),
        );
        let resolved = resolved_metadata(
            metadata,
            Arc::new(b"response-body-never-log".to_vec()),
            ClientMetadataCacheValidators {
                etag: Some("etag-never-log".to_owned()),
                last_modified: None,
            },
            OffsetDateTime::UNIX_EPOCH,
            CachePolicy {
                cacheable: true,
                freshness_lifetime: Duration::from_secs(60),
            },
        );
        let debug = format!("{resolved:?}");
        for forbidden in [
            secret,
            "response-body-never-log",
            "etag-never-log",
            "Example Client",
        ] {
            assert!(
                !debug.contains(forbidden),
                "debug output leaked {forbidden}"
            );
        }
    }
}
