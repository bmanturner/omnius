use std::{fmt, time::Duration};

use omnius_config::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Absolute safety ceiling for one search query.
pub const HARD_MAX_QUERY_BYTES: usize = 1_024;
/// Absolute safety ceiling for the rendered provider filter.
pub const HARD_MAX_FILTER_BYTES: usize = 8_192;
/// Absolute safety ceiling for one provider result page.
pub const HARD_MAX_HITS: usize = 100;
/// Absolute safety ceiling for search offsets.
pub const HARD_MAX_OFFSET: usize = 10_000;
/// Absolute safety ceiling for one indexed document.
pub const HARD_MAX_DOCUMENT_BYTES: usize = 262_144;

const MAX_PROVIDER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_STALE_AFTER: Duration = Duration::from_hours(168);
const MAX_TASK_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_API_KEY_BYTES: usize = 4_096;
const MAX_PREFIX_BYTES: usize = 48;

/// Validated bounds applied before any provider request is made.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SearchLimits {
    /// Maximum UTF-8 bytes accepted for query text.
    pub max_query_bytes: usize,
    /// Maximum bytes accepted for the complete rendered filter.
    pub max_filter_bytes: usize,
    /// Maximum provider hits requested at once.
    pub max_hits: usize,
    /// Maximum number of hits passed to the batch reauthorizer.
    pub max_reauthorization_batch: usize,
    /// Maximum accepted offset.
    pub max_offset: usize,
    /// Maximum serialized bytes accepted for one projection document.
    pub max_document_bytes: usize,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_query_bytes: 512,
            max_filter_bytes: 4_096,
            max_hits: 50,
            max_reauthorization_batch: 50,
            max_offset: 5_000,
            max_document_bytes: 65_536,
        }
    }
}

impl SearchLimits {
    pub(crate) fn validate(self) -> Result<Self, SearchConfigError> {
        if !(1..=HARD_MAX_QUERY_BYTES).contains(&self.max_query_bytes) {
            return Err(SearchConfigError::InvalidQueryLimit);
        }
        if !(64..=HARD_MAX_FILTER_BYTES).contains(&self.max_filter_bytes) {
            return Err(SearchConfigError::InvalidFilterLimit);
        }
        if !(1..=HARD_MAX_HITS).contains(&self.max_hits) {
            return Err(SearchConfigError::InvalidHitLimit);
        }
        if !(self.max_hits..=HARD_MAX_HITS).contains(&self.max_reauthorization_batch) {
            return Err(SearchConfigError::InvalidReauthorizationLimit);
        }
        if self.max_offset > HARD_MAX_OFFSET {
            return Err(SearchConfigError::InvalidOffsetLimit);
        }
        if !(1_024..=HARD_MAX_DOCUMENT_BYTES).contains(&self.max_document_bytes) {
            return Err(SearchConfigError::InvalidDocumentLimit);
        }
        Ok(self)
    }
}

/// Meilisearch connection, deadline, staleness, and memory-bound configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchMeilisearchConfig {
    /// Base URL of the Meilisearch API.
    pub endpoint: Url,
    /// Provider API key. Debug output always redacts it.
    pub api_key: SecretString,
    /// Portable prefix prepended to every owned index UID.
    pub index_prefix: String,
    /// End-to-end deadline around each SDK operation, including task polling.
    #[serde(with = "humantime_serde")]
    pub provider_timeout: Duration,
    /// Interval used while waiting for asynchronous Meilisearch tasks.
    #[serde(with = "humantime_serde")]
    pub task_poll_interval: Duration,
    /// Maximum age of the latest completed projection before health degrades.
    #[serde(with = "humantime_serde")]
    pub stale_after: Duration,
    /// Projection lease, which must safely exceed the provider deadline.
    #[serde(with = "humantime_serde")]
    pub projection_lease: Duration,
    /// Request and document safety bounds.
    pub limits: SearchLimits,
}

impl fmt::Debug for SearchMeilisearchConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchMeilisearchConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("index_prefix", &self.index_prefix)
            .field("provider_timeout", &self.provider_timeout)
            .field("task_poll_interval", &self.task_poll_interval)
            .field("stale_after", &self.stale_after)
            .field("projection_lease", &self.projection_lease)
            .field("limits", &self.limits)
            .finish()
    }
}

impl SearchMeilisearchConfig {
    /// Validates the configuration before constructing network or storage adapters.
    ///
    /// # Errors
    ///
    /// Returns [`SearchConfigError`] when a URL, secret, name, duration, or bound is unsafe.
    pub fn validate(&self) -> Result<(), SearchConfigError> {
        if !matches!(self.endpoint.scheme(), "http" | "https")
            || self.endpoint.cannot_be_a_base()
            || !self.endpoint.username().is_empty()
            || self.endpoint.password().is_some()
            || self.endpoint.query().is_some()
            || self.endpoint.fragment().is_some()
            || self.endpoint.path() != "/"
        {
            return Err(SearchConfigError::InvalidEndpoint);
        }
        let key_len = self.api_key.expose_secret().len();
        if !(1..=MAX_API_KEY_BYTES).contains(&key_len) {
            return Err(SearchConfigError::InvalidApiKey);
        }
        if !portable_name(&self.index_prefix, MAX_PREFIX_BYTES) {
            return Err(SearchConfigError::InvalidIndexPrefix);
        }
        if self.provider_timeout.is_zero() || self.provider_timeout > MAX_PROVIDER_TIMEOUT {
            return Err(SearchConfigError::InvalidProviderTimeout);
        }
        if self.task_poll_interval.is_zero()
            || self.task_poll_interval > MAX_TASK_POLL_INTERVAL
            || self.task_poll_interval >= self.provider_timeout
        {
            return Err(SearchConfigError::InvalidTaskPollInterval);
        }
        if self.stale_after < self.provider_timeout || self.stale_after > MAX_STALE_AFTER {
            return Err(SearchConfigError::InvalidStalenessWindow);
        }
        let minimum_lease = self
            .provider_timeout
            .checked_add(Duration::from_secs(1))
            .ok_or(SearchConfigError::InvalidProjectionLease)?;
        if self.projection_lease < minimum_lease || self.projection_lease > MAX_STALE_AFTER {
            return Err(SearchConfigError::InvalidProjectionLease);
        }
        self.limits.validate()?;
        Ok(())
    }

    pub(crate) fn endpoint_without_trailing_slash(&self) -> &str {
        self.endpoint.as_str().trim_end_matches('/')
    }
}

/// Invalid search-provider configuration with no secret-bearing fields.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SearchConfigError {
    /// The endpoint was not a plain HTTP(S) origin URL.
    #[error("search endpoint must be an HTTP(S) origin URL")]
    InvalidEndpoint,
    /// The provider key was empty or unreasonably large.
    #[error("search API key is invalid")]
    InvalidApiKey,
    /// The index prefix was not a bounded portable identifier.
    #[error("search index prefix is invalid")]
    InvalidIndexPrefix,
    /// The provider deadline was zero or exceeded the hard ceiling.
    #[error("search provider timeout is invalid")]
    InvalidProviderTimeout,
    /// The asynchronous task poll interval was invalid.
    #[error("search task poll interval is invalid")]
    InvalidTaskPollInterval,
    /// The staleness window was shorter than a request or exceeded one week.
    #[error("search staleness window is invalid")]
    InvalidStalenessWindow,
    /// The projection lease could expire while a bounded provider call is live.
    #[error("search projection lease is invalid")]
    InvalidProjectionLease,
    /// The configured query bound was invalid.
    #[error("search query byte bound is invalid")]
    InvalidQueryLimit,
    /// The configured filter bound was invalid.
    #[error("search filter byte bound is invalid")]
    InvalidFilterLimit,
    /// The configured hit bound was invalid.
    #[error("search hit bound is invalid")]
    InvalidHitLimit,
    /// The configured batch reauthorization bound was smaller than the hit bound.
    #[error("search reauthorization batch bound is invalid")]
    InvalidReauthorizationLimit,
    /// The configured offset bound exceeded the hard ceiling.
    #[error("search offset bound is invalid")]
    InvalidOffsetLimit,
    /// The configured document bound was invalid.
    #[error("search document byte bound is invalid")]
    InvalidDocumentLimit,
}

fn portable_name(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}
