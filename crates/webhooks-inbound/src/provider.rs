use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use bytes::Bytes;
use hmac::{Hmac, KeyInit as _, Mac as _};
use http::{HeaderMap, HeaderName, StatusCode};
use rsk_config::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_SCOPE_BYTES: usize = 255;
const MAX_EVENT_ID_BYTES: usize = 255;
const MAX_EVENT_TYPE_BYTES: usize = 128;
const MAX_PROVIDER_COUNT: usize = 32;
const RECEIPT_FENCE_GRACE: Duration = Duration::from_secs(1);
const SIGNATURE_PREFIX: &str = "v1=";

/// Validated, bounded provider identifier used for routing and database fencing.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    /// Parses an identifier containing lowercase ASCII letters, digits, `.`, `_`, or `-`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when the identifier is empty, oversized, or malformed.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if valid_identifier(&value, MAX_PROVIDER_ID_BYTES) {
            Ok(Self(value))
        } else {
            Err(IdentifierError)
        }
    }

    /// Returns the stable route and persistence representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ProviderId").field(&self.0).finish()
    }
}

/// A provider, scope, or event identifier is outside its public safe syntax.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("webhook identifier is invalid")]
pub struct IdentifierError;

/// Metadata authenticated by a provider adapter before the body is parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRequest {
    provider: ProviderId,
    scope: String,
    event_id: String,
    provider_timestamp: OffsetDateTime,
}

impl VerifiedRequest {
    /// Returns the configured provider identifier.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the provider-specific replay scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the provider event identity inside the replay scope.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Returns the provider timestamp covered by the signature.
    #[must_use]
    pub const fn provider_timestamp(&self) -> OffsetDateTime {
        self.provider_timestamp
    }

    pub(crate) fn into_parts(self) -> (ProviderId, String, String, OffsetDateTime) {
        (
            self.provider,
            self.scope,
            self.event_id,
            self.provider_timestamp,
        )
    }
}

/// Versioned provider event produced only after successful raw-body verification.
#[derive(Clone)]
pub struct ParsedProviderEvent {
    event_type: String,
    version: u16,
    occurred_at: Option<OffsetDateTime>,
    safe_payload: Value,
}

impl ParsedProviderEvent {
    /// Creates a bounded provider event envelope.
    ///
    /// The payload must already be a provider-selected safe projection. Raw signed bodies and
    /// signature material must never be placed in it.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Rejected`] when the event type or version is invalid.
    pub fn new(
        event_type: impl Into<String>,
        version: u16,
        occurred_at: Option<OffsetDateTime>,
        safe_payload: Value,
    ) -> Result<Self, ParseError> {
        let event_type = event_type.into();
        if !valid_identifier(&event_type, MAX_EVENT_TYPE_BYTES) || version == 0 {
            return Err(ParseError::Rejected);
        }
        Ok(Self {
            event_type,
            version,
            occurred_at,
            safe_payload,
        })
    }

    /// Returns the provider-specific event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns the provider schema version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the optional occurrence time declared by the provider event.
    #[must_use]
    pub const fn occurred_at(&self) -> Option<OffsetDateTime> {
        self.occurred_at
    }

    /// Returns the bounded safe projection selected by the provider adapter.
    #[must_use]
    pub const fn safe_payload(&self) -> &Value {
        &self.safe_payload
    }

    pub(crate) fn into_parts(self) -> (String, u16, Option<OffsetDateTime>, Value) {
        (
            self.event_type,
            self.version,
            self.occurred_at,
            self.safe_payload,
        )
    }
}

impl fmt::Debug for ParsedProviderEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedProviderEvent")
            .field("event_type", &self.event_type)
            .field("version", &self.version)
            .field("occurred_at", &self.occurred_at)
            .field("safe_payload", &"[REDACTED]")
            .finish()
    }
}

/// Durable receive classification passed back to the provider-specific acknowledgement policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgementDisposition {
    /// A new receipt was committed.
    Accepted,
    /// The exact event and content digest were already committed.
    Duplicate,
    /// The event identity was reused with different signed bytes.
    Conflict,
}

/// Bounded provider-specific HTTP acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResponse {
    /// HTTP status required by the provider contract.
    pub status: StatusCode,
    /// Optional fixed response content type.
    pub content_type: Option<&'static str>,
    /// Bounded fixed response body.
    pub body: Bytes,
}

/// Safe verification failure. It deliberately carries no header, signature, body, or secret.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationError {
    /// Required signed material was absent, duplicated, malformed, or failed verification.
    #[error("webhook verification rejected")]
    Rejected,
    /// The authenticated timestamp is older than the configured replay window.
    #[error("webhook timestamp rejected")]
    Stale,
    /// The authenticated timestamp exceeds the configured future tolerance.
    #[error("webhook timestamp rejected")]
    Future,
}

/// Safe post-verification provider parsing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ParseError {
    /// The verified body uses a schema version unsupported by this adapter.
    #[error("webhook event version is unsupported")]
    UnsupportedVersion,
    /// The verified body is malformed or violates the provider envelope.
    #[error("webhook event is invalid")]
    Rejected,
}

/// Provider seam that preserves verification and versioned parsing as separate operations.
pub trait ProviderAdapter: Send + Sync + 'static {
    /// Returns the bounded provider route identifier.
    fn provider_id(&self) -> &ProviderId;

    /// Returns the maximum authenticated timestamp age accepted by this adapter.
    fn replay_window(&self) -> Duration;

    /// Returns the maximum accepted future clock skew for authenticated timestamps.
    fn future_tolerance(&self) -> Duration;

    /// Verifies exact raw bytes, signed headers, and timestamp without parsing the event body.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`VerificationError`] for every rejection.
    fn verify(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now: OffsetDateTime,
    ) -> Result<VerifiedRequest, VerificationError>;

    /// Parses a provider-owned versioned event after successful verification.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ParseError`] when the verified bytes do not match a supported
    /// provider schema.
    fn parse(
        &self,
        verified: &VerifiedRequest,
        raw_body: &[u8],
    ) -> Result<ParsedProviderEvent, ParseError>;

    /// Produces the provider-specific response after the durable receive decision commits.
    fn acknowledgement(&self, disposition: AcknowledgementDisposition) -> ProviderResponse;
}

/// Immutable registry of configured provider adapters.
#[derive(Clone, Default)]
pub struct ProviderRegistry {
    adapters: Arc<HashMap<ProviderId, Arc<dyn ProviderAdapter>>>,
    minimum_receipt_retention: Duration,
}

impl ProviderRegistry {
    /// Builds a registry and rejects duplicate provider identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when the registry is oversized or two adapters own one route.
    pub fn new(
        adapters: impl IntoIterator<Item = Arc<dyn ProviderAdapter>>,
    ) -> Result<Self, RegistryError> {
        let mut registered = HashMap::new();
        let mut minimum_receipt_retention = Duration::ZERO;
        for adapter in adapters {
            let accepted_lifetime = adapter
                .replay_window()
                .saturating_add(adapter.future_tolerance())
                .saturating_add(RECEIPT_FENCE_GRACE);
            minimum_receipt_retention = minimum_receipt_retention.max(accepted_lifetime);
            if registered.len() >= MAX_PROVIDER_COUNT {
                return Err(RegistryError::TooManyProviders);
            }
            let provider = adapter.provider_id().clone();
            if registered.insert(provider, adapter).is_some() {
                return Err(RegistryError::DuplicateProvider);
            }
        }
        Ok(Self {
            adapters: Arc::new(registered),
            minimum_receipt_retention,
        })
    }

    /// Resolves one validated provider route without exposing the configured provider set.
    #[must_use]
    pub fn get(&self, provider: &str) -> Option<&Arc<dyn ProviderAdapter>> {
        self.adapters
            .iter()
            .find_map(|(id, adapter)| (id.as_str() == provider).then_some(adapter))
    }

    /// Returns the bounded number of configured providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Returns whether no providers are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// Returns the minimum fence retention covering all inclusive timestamp acceptance windows.
    #[must_use]
    pub const fn minimum_receipt_retention(&self) -> Duration {
        self.minimum_receipt_retention
    }
}

impl fmt::Debug for ProviderRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRegistry")
            .field("provider_count", &self.adapters.len())
            .field("minimum_receipt_retention", &self.minimum_receipt_retention)
            .finish()
    }
}
/// Provider registry construction failed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    /// The provider set exceeds the fixed low-cardinality bound.
    #[error("webhook provider registry is too large")]
    TooManyProviders,
    /// More than one adapter claimed the same provider route.
    #[error("duplicate webhook provider configuration")]
    DuplicateProvider,
}

pub(crate) struct FixtureVerificationPolicy {
    signature_header: HeaderName,
    timestamp_header: HeaderName,
    replay_window: Duration,
    future_tolerance: Duration,
}

impl FixtureVerificationPolicy {
    pub(crate) const fn new(
        signature_header: HeaderName,
        timestamp_header: HeaderName,
        replay_window: Duration,
        future_tolerance: Duration,
    ) -> Self {
        Self {
            signature_header,
            timestamp_header,
            replay_window,
            future_tolerance,
        }
    }
}

/// Explicit deterministic test/development signing scheme.
///
/// The signature uses a domain-separated, provider-bound, length-prefixed binary transcript.
/// This is a fixture protocol, not a universal provider webhook schema.
pub struct FixtureHmacSha256Adapter {
    provider: ProviderId,
    verification: FixtureVerificationPolicy,
    scope_header: HeaderName,
    event_id_header: HeaderName,
    secrets: Vec<SecretString>,
}

impl fmt::Debug for FixtureHmacSha256Adapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureHmacSha256Adapter")
            .field("provider", &self.provider)
            .field("signature_header", &self.verification.signature_header)
            .field("timestamp_header", &self.verification.timestamp_header)
            .field("scope_header", &self.scope_header)
            .field("event_id_header", &self.event_id_header)
            .field("secrets", &"[REDACTED]")
            .field("replay_window", &self.verification.replay_window)
            .field("future_tolerance", &self.verification.future_tolerance)
            .finish()
    }
}

impl FixtureHmacSha256Adapter {
    /// Creates the deterministic fixture adapter from already validated configuration.
    #[must_use]
    pub(crate) fn new(
        provider: ProviderId,
        verification: FixtureVerificationPolicy,
        scope_header: HeaderName,
        event_id_header: HeaderName,
        secrets: Vec<SecretString>,
    ) -> Self {
        Self {
            provider,
            verification,
            scope_header,
            event_id_header,
            secrets,
        }
    }
}

impl ProviderAdapter for FixtureHmacSha256Adapter {
    fn provider_id(&self) -> &ProviderId {
        &self.provider
    }

    fn replay_window(&self) -> Duration {
        self.verification.replay_window
    }

    fn future_tolerance(&self) -> Duration {
        self.verification.future_tolerance
    }

    fn verify(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now: OffsetDateTime,
    ) -> Result<VerifiedRequest, VerificationError> {
        let signature = exactly_one_header(headers, &self.verification.signature_header)?;
        let timestamp = exactly_one_header(headers, &self.verification.timestamp_header)?;
        let scope = exactly_one_header(headers, &self.scope_header)?;
        let event_id = exactly_one_header(headers, &self.event_id_header)?;
        if !valid_external_identifier(scope, MAX_SCOPE_BYTES)
            || !valid_external_identifier(event_id, MAX_EVENT_ID_BYTES)
        {
            return Err(VerificationError::Rejected);
        }
        let timestamp_seconds = timestamp
            .parse::<i64>()
            .map_err(|_| VerificationError::Rejected)?;
        let provider_timestamp = OffsetDateTime::from_unix_timestamp(timestamp_seconds)
            .map_err(|_| VerificationError::Rejected)?;
        let replay_seconds = i64::try_from(self.verification.replay_window.as_secs())
            .map_err(|_| VerificationError::Rejected)?;
        let future_seconds = i64::try_from(self.verification.future_tolerance.as_secs())
            .map_err(|_| VerificationError::Rejected)?;
        if timestamp_seconds < now.unix_timestamp().saturating_sub(replay_seconds) {
            return Err(VerificationError::Stale);
        }
        if timestamp_seconds > now.unix_timestamp().saturating_add(future_seconds) {
            return Err(VerificationError::Future);
        }
        let supplied = decode_signature(signature)?;
        let mut verified = false;
        for secret in &self.secrets {
            let valid = fixture_mac(
                secret.expose_secret().as_bytes(),
                self.provider.as_str().as_bytes(),
                timestamp.as_bytes(),
                scope.as_bytes(),
                event_id.as_bytes(),
                raw_body,
            )
            .is_ok_and(|mac| mac.verify_slice(&supplied).is_ok());
            verified |= valid;
        }
        if !verified {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedRequest {
            provider: self.provider.clone(),
            scope: scope.to_owned(),
            event_id: event_id.to_owned(),
            provider_timestamp,
        })
    }

    fn parse(
        &self,
        _verified: &VerifiedRequest,
        raw_body: &[u8],
    ) -> Result<ParsedProviderEvent, ParseError> {
        let event: FixtureEvent =
            serde_json::from_slice(raw_body).map_err(|_| ParseError::Rejected)?;
        if event.version != 1 {
            return Err(ParseError::UnsupportedVersion);
        }
        let occurred_at = event
            .occurred_at_unix_seconds
            .map(OffsetDateTime::from_unix_timestamp)
            .transpose()
            .map_err(|_| ParseError::Rejected)?;
        ParsedProviderEvent::new(event.event_type, event.version, occurred_at, event.data)
    }

    fn acknowledgement(&self, disposition: AcknowledgementDisposition) -> ProviderResponse {
        ProviderResponse {
            status: match disposition {
                AcknowledgementDisposition::Accepted | AcknowledgementDisposition::Duplicate => {
                    StatusCode::ACCEPTED
                }
                AcknowledgementDisposition::Conflict => StatusCode::CONFLICT,
            },
            content_type: None,
            body: Bytes::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvent {
    version: u16,
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    occurred_at_unix_seconds: Option<i64>,
    data: Value,
}

/// Signs one fixture request according to [`FixtureHmacSha256Adapter`].
///
/// # Errors
///
/// Returns [`FixtureSigningError`] when the key or a transcript field cannot be represented.
pub fn sign_fixture_request(
    secret: &[u8],
    provider: &str,
    timestamp: i64,
    scope: &str,
    event_id: &str,
    raw_body: &[u8],
) -> Result<String, FixtureSigningError> {
    let timestamp = timestamp.to_string();
    let mac = fixture_mac(
        secret,
        provider.as_bytes(),
        timestamp.as_bytes(),
        scope.as_bytes(),
        event_id.as_bytes(),
        raw_body,
    )?;
    let bytes = mac.finalize().into_bytes();
    let mut encoded = String::with_capacity(SIGNATURE_PREFIX.len() + bytes.len() * 2);
    encoded.push_str(SIGNATURE_PREFIX);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_| FixtureSigningError)?;
    }
    Ok(encoded)
}

/// Fixture request signing failed without exposing signing material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("fixture webhook signing failed")]
pub struct FixtureSigningError;

fn fixture_mac(
    secret: &[u8],
    provider: &[u8],
    timestamp: &[u8],
    scope: &[u8],
    event_id: &[u8],
    raw_body: &[u8],
) -> Result<Hmac<Sha256>, FixtureSigningError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| FixtureSigningError)?;
    mac.update(b"rsk.fixture-hmac-sha256.v1\0");
    update_transcript_field(&mut mac, provider)?;
    update_transcript_field(&mut mac, timestamp)?;
    update_transcript_field(&mut mac, scope)?;
    update_transcript_field(&mut mac, event_id)?;
    update_transcript_field(&mut mac, raw_body)?;
    Ok(mac)
}

fn update_transcript_field(
    mac: &mut Hmac<Sha256>,
    value: &[u8],
) -> Result<(), FixtureSigningError> {
    let length = u64::try_from(value.len()).map_err(|_| FixtureSigningError)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn exactly_one_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<&'a str, VerificationError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(VerificationError::Rejected)?;
    if values.next().is_some() {
        return Err(VerificationError::Rejected);
    }
    value.to_str().map_err(|_| VerificationError::Rejected)
}

fn decode_signature(value: &str) -> Result<[u8; 32], VerificationError> {
    let hex = value
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or(VerificationError::Rejected)?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(VerificationError::Rejected);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0]).ok_or(VerificationError::Rejected)?;
        let low = hex_nibble(pair[1]).ok_or(VerificationError::Rejected)?;
        decoded[index] = high << 4 | low;
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    value.len() <= maximum
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_external_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;

    const SECRET: &[u8] = b"fixture-secret-material-with-32-bytes-minimum";
    const OLD_SECRET: &[u8] = b"old-fixture-secret-material-with-32-bytes";
    const NOW: i64 = 1_800_000_000;

    fn adapter() -> FixtureHmacSha256Adapter {
        FixtureHmacSha256Adapter::new(
            ProviderId::parse("fixture").unwrap_or_else(|_| unreachable!()),
            FixtureVerificationPolicy::new(
                HeaderName::from_static("x-fixture-signature"),
                HeaderName::from_static("x-fixture-timestamp"),
                Duration::from_secs(300),
                Duration::from_secs(30),
            ),
            HeaderName::from_static("x-fixture-scope"),
            HeaderName::from_static("x-fixture-event-id"),
            vec![
                SecretString::from("fixture-secret-material-with-32-bytes-minimum".to_owned()),
                SecretString::from("old-fixture-secret-material-with-32-bytes".to_owned()),
            ],
        )
    }

    fn body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 1,
            "type": "invoice.paid",
            "occurred_at_unix_seconds": NOW,
            "data": {"invoice": "safe-reference"}
        }))
        .unwrap_or_else(|_| unreachable!())
    }

    fn headers(secret: &[u8], raw: &[u8], timestamp: i64) -> HeaderMap {
        let signature =
            sign_fixture_request(secret, "fixture", timestamp, "tenant/one", "evt_1", raw)
                .unwrap_or_else(|_| unreachable!());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-fixture-signature",
            HeaderValue::from_str(&signature).unwrap_or_else(|_| unreachable!()),
        );
        headers.insert(
            "x-fixture-timestamp",
            HeaderValue::from_str(&timestamp.to_string()).unwrap_or_else(|_| unreachable!()),
        );
        headers.insert("x-fixture-scope", HeaderValue::from_static("tenant/one"));
        headers.insert("x-fixture-event-id", HeaderValue::from_static("evt_1"));
        headers
    }

    #[test]
    fn raw_byte_mutation_invalidates_signature_before_parsing() {
        let raw = body();
        let signed = headers(SECRET, &raw, NOW);
        let mut mutated = raw.clone();
        mutated.push(b' ');
        assert_eq!(
            adapter().verify(
                &signed,
                &mutated,
                OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH)
            ),
            Err(VerificationError::Rejected)
        );
    }

    #[test]
    fn duplicate_signature_or_timestamp_headers_are_rejected() {
        let raw = body();
        let mut signed = headers(SECRET, &raw, NOW);
        signed.append(
            "x-fixture-signature",
            HeaderValue::from_static(
                "v1=0000000000000000000000000000000000000000000000000000000000000000",
            ),
        );
        assert_eq!(
            adapter().verify(
                &signed,
                &raw,
                OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH)
            ),
            Err(VerificationError::Rejected)
        );

        let mut signed = headers(SECRET, &raw, NOW);
        signed.append(
            "x-fixture-timestamp",
            HeaderValue::from_static("1800000000"),
        );
        assert_eq!(
            adapter().verify(
                &signed,
                &raw,
                OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH)
            ),
            Err(VerificationError::Rejected)
        );
    }

    #[test]
    fn timestamp_edges_are_inclusive_but_stale_and_future_values_fail() {
        let raw = body();
        let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        for accepted in [NOW - 300, NOW + 30] {
            assert!(
                adapter()
                    .verify(&headers(SECRET, &raw, accepted), &raw, now)
                    .is_ok()
            );
        }
        assert_eq!(
            adapter().verify(&headers(SECRET, &raw, NOW - 301), &raw, now),
            Err(VerificationError::Stale)
        );
        assert_eq!(
            adapter().verify(&headers(SECRET, &raw, NOW + 31), &raw, now),
            Err(VerificationError::Future)
        );
    }

    #[test]
    fn rotated_current_and_previous_keys_verify() {
        let raw = body();
        let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        assert!(
            adapter()
                .verify(&headers(SECRET, &raw, NOW), &raw, now)
                .is_ok()
        );
        assert!(
            adapter()
                .verify(&headers(OLD_SECRET, &raw, NOW), &raw, now)
                .is_ok()
        );
    }

    #[test]
    fn transcript_binds_provider_and_unambiguous_identity_fields() -> Result<(), FixtureSigningError>
    {
        let raw = body();
        let canonical = sign_fixture_request(SECRET, "fixture", NOW, "tenant.one", "evt_1", &raw)?;
        let other_provider =
            sign_fixture_request(SECRET, "other", NOW, "tenant.one", "evt_1", &raw)?;
        let ambiguous_split =
            sign_fixture_request(SECRET, "fixture", NOW, "tenant", "one.evt_1", &raw)?;
        assert_ne!(canonical, other_provider);
        assert_ne!(canonical, ambiguous_split);
        Ok(())
    }
}
