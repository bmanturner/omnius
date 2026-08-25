use std::{fmt, io, sync::Arc, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use metrics::counter;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AcknowledgementDisposition, NewReceipt, ProviderRegistry, ProviderResponse, ReceiptRepository,
    ReceiveDisposition,
};

/// Exact raw request accepted by the transport-neutral receive service.
pub struct RawWebhookRequest {
    /// Route-selected provider identifier.
    pub provider: String,
    /// Complete HTTP header map before provider verification.
    pub headers: HeaderMap,
    /// Exact, unparsed request body bytes.
    pub body: Bytes,
}

impl fmt::Debug for RawWebhookRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawWebhookRequest")
            .field("provider", &self.provider)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

/// Bounded receive-time resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveLimits {
    /// Maximum exact raw request bytes.
    pub max_body_bytes: usize,
    /// Maximum header-value count.
    pub max_header_count: usize,
    /// Maximum aggregate header-name and value bytes.
    pub max_header_bytes: usize,
    /// Maximum serialized provider-selected safe payload bytes.
    pub max_safe_payload_bytes: usize,
}

/// Verified receive pipeline that never invokes domain handlers synchronously.
#[derive(Clone)]
pub struct InboundWebhookService {
    providers: ProviderRegistry,
    receipts: Arc<dyn ReceiptRepository>,
    limits: ReceiveLimits,
    retention: time::Duration,
}

impl InboundWebhookService {
    /// Builds the receive service from an immutable provider registry and durable receipt store.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiveBuildError`] when durable receipt retention cannot cover the longest
    /// inclusive timestamp acceptance lifetime in the provider registry.
    pub fn new(
        providers: ProviderRegistry,
        receipts: Arc<dyn ReceiptRepository>,
        limits: ReceiveLimits,
        retention: Duration,
    ) -> Result<Self, ReceiveBuildError> {
        if retention.is_zero() || retention < providers.minimum_receipt_retention() {
            return Err(ReceiveBuildError::InvalidRetention);
        }
        let retention =
            time::Duration::try_from(retention).map_err(|_| ReceiveBuildError::InvalidRetention)?;
        Ok(Self {
            providers,
            receipts,
            limits,
            retention,
        })
    }

    /// Applies limits, verifies exact bytes and timestamp, parses a versioned provider event,
    /// atomically fences replay/deduplication, and only then returns the provider acknowledgement.
    ///
    /// This method deliberately has no handler dependency. A successful response proves the
    /// receipt commit, not completion of asynchronous domain processing.
    ///
    /// # Errors
    ///
    /// Returns a safe [`ReceiveError`] for resource rejection, unknown provider, failed
    /// verification/parsing, or unavailable durable persistence. Rejections before persistence
    /// create no receipt.
    pub async fn receive(
        &self,
        request: RawWebhookRequest,
        now: OffsetDateTime,
    ) -> Result<ProviderResponse, ReceiveError> {
        if request.body.len() > self.limits.max_body_bytes || !self.headers_within(&request.headers)
        {
            record_receive("unknown", "limit");
            return Err(ReceiveError::LimitExceeded);
        }
        let adapter = self
            .providers
            .get(&request.provider)
            .ok_or(ReceiveError::UnknownProvider)?;
        let provider_label = adapter.provider_id().as_str();
        let verified = adapter
            .verify(&request.headers, &request.body, now)
            .map_err(|_| {
                record_receive(provider_label, "rejected");
                ReceiveError::Rejected
            })?;
        let parsed = adapter.parse(&verified, &request.body).map_err(|_| {
            record_receive(provider_label, "rejected");
            ReceiveError::Rejected
        })?;
        if !serialized_payload_within(parsed.safe_payload(), self.limits.max_safe_payload_bytes) {
            record_receive(provider_label, "limit");
            return Err(ReceiveError::LimitExceeded);
        }
        let retain_until = now.checked_add(self.retention).ok_or_else(|| {
            record_receive(provider_label, "unavailable");
            ReceiveError::Unavailable
        })?;
        let digest: [u8; 32] = Sha256::digest(&request.body).into();
        let receipt = NewReceipt::from_verified(verified, parsed, digest, now, retain_until);
        let disposition = self.receipts.receive(&receipt).await.map_err(|_| {
            record_receive(provider_label, "unavailable");
            ReceiveError::Unavailable
        })?;
        let acknowledgement = match disposition {
            ReceiveDisposition::Accepted(_) => AcknowledgementDisposition::Accepted,
            ReceiveDisposition::Duplicate(_) => AcknowledgementDisposition::Duplicate,
            ReceiveDisposition::Conflict => AcknowledgementDisposition::Conflict,
        };
        record_receive(
            provider_label,
            match acknowledgement {
                AcknowledgementDisposition::Accepted => "accepted",
                AcknowledgementDisposition::Duplicate => "duplicate",
                AcknowledgementDisposition::Conflict => "conflict",
            },
        );
        Ok(adapter.acknowledgement(acknowledgement))
    }

    /// Returns the exact raw-body route limit.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.limits.max_body_bytes
    }

    pub(crate) fn headers_within(&self, headers: &HeaderMap) -> bool {
        headers.len() <= self.limits.max_header_count
            && header_bytes(headers) <= self.limits.max_header_bytes
    }
}

impl fmt::Debug for InboundWebhookService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundWebhookService")
            .field("providers", &self.providers)
            .field("receipts", &"[DURABLE STORE]")
            .field("limits", &self.limits)
            .field("retention", &self.retention)
            .finish()
    }
}

/// Receive-service construction failed without exposing provider configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReceiveBuildError {
    /// Receipt retention is zero or cannot cover the inclusive timestamp acceptance lifetime.
    #[error("webhook receipt retention does not cover provider acceptance policy")]
    InvalidRetention,
}

/// Safe receive-pipeline failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReceiveError {
    /// Body, header, or safe parsed payload exceeds configured bounds.
    #[error("webhook request exceeds configured limits")]
    LimitExceeded,
    /// No configured adapter owns the route identifier.
    #[error("webhook provider is not configured")]
    UnknownProvider,
    /// Verification, timestamp, or post-verification parsing rejected the request.
    #[error("webhook request was rejected")]
    Rejected,
    /// Durable receipt persistence is unavailable.
    #[error("webhook receipt service is unavailable")]
    Unavailable,
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
    })
}

fn serialized_payload_within(payload: &serde_json::Value, limit: usize) -> bool {
    let mut counter = BoundedCounter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, payload).is_ok()
}

struct BoundedCounter {
    bytes: usize,
    limit: usize,
}

impl io::Write for BoundedCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized webhook payload is too large"))?;
        if next > self.limit {
            return Err(io::Error::other("serialized webhook payload is too large"));
        }
        self.bytes = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn record_receive(provider: &str, outcome: &'static str) {
    counter!(
        "rsk_webhooks_inbound_receive_total",
        "provider" => provider.to_owned(),
        "outcome" => outcome
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use futures::future::BoxFuture;
    use http::HeaderValue;
    use rsk_config::SecretString;
    use serde_json::json;

    use super::*;
    use crate::{
        FixtureHmacProviderConfig, ProcessorConfig, ReceiptId, ReceiptStoreError, WebhookConfig,
        sign_fixture_request,
    };

    const SECRET: &str = "fixture-secret-material-with-at-least-thirty-two-bytes";
    const NOW: i64 = 1_800_000_000;

    #[derive(Default)]
    struct CapturingStore {
        writes: AtomicUsize,
        disposition: Mutex<Option<ReceiveDisposition>>,
    }

    impl ReceiptRepository for CapturingStore {
        fn receive<'a>(
            &'a self,
            receipt: &'a NewReceipt,
        ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>> {
            Box::pin(async move {
                self.writes.fetch_add(1, Ordering::SeqCst);
                let disposition = self
                    .disposition
                    .lock()
                    .ok()
                    .and_then(|mut value| value.take())
                    .unwrap_or(ReceiveDisposition::Accepted(receipt.id()));
                Ok(disposition)
            })
        }
    }

    fn service(store: Arc<CapturingStore>) -> InboundWebhookService {
        let config = WebhookConfig {
            enabled: true,
            processing: ProcessorConfig::default(),
            fixture_hmac_providers: vec![FixtureHmacProviderConfig {
                provider: "fixture".to_owned(),
                signature_header: "x-fixture-signature".to_owned(),
                timestamp_header: "x-fixture-timestamp".to_owned(),
                scope_header: "x-fixture-scope".to_owned(),
                event_id_header: "x-fixture-event-id".to_owned(),
                secrets: vec![SecretString::from(SECRET.to_owned())],
                replay_window: Duration::from_secs(300),
                future_tolerance: Duration::from_secs(30),
            }],
            ..WebhookConfig::default()
        };
        InboundWebhookService::new(
            config.build_registry().unwrap_or_else(|_| unreachable!()),
            store,
            ReceiveLimits {
                max_body_bytes: config.max_body_bytes,
                max_header_count: config.max_header_count,
                max_header_bytes: config.max_header_bytes,
                max_safe_payload_bytes: config.max_safe_payload_bytes,
            },
            config.retention,
        )
        .unwrap_or_else(|_| unreachable!())
    }

    fn request(raw: Bytes) -> RawWebhookRequest {
        let signature = sign_fixture_request(
            SECRET.as_bytes(),
            "fixture",
            NOW,
            "tenant/one",
            "evt_1",
            &raw,
        )
        .unwrap_or_else(|_| unreachable!());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-fixture-signature",
            HeaderValue::from_str(&signature).unwrap_or_else(|_| unreachable!()),
        );
        headers.insert(
            "x-fixture-timestamp",
            HeaderValue::from_static("1800000000"),
        );
        headers.insert("x-fixture-scope", HeaderValue::from_static("tenant/one"));
        headers.insert("x-fixture-event-id", HeaderValue::from_static("evt_1"));
        RawWebhookRequest {
            provider: "fixture".to_owned(),
            headers,
            body: raw,
        }
    }

    fn body() -> Bytes {
        Bytes::from(
            serde_json::to_vec(&json!({
                "version": 1,
                "type": "invoice.paid",
                "data": {"reference": "safe"}
            }))
            .unwrap_or_else(|_| unreachable!()),
        )
    }

    #[tokio::test]
    async fn acknowledgement_only_requires_commit_and_never_runs_a_handler() {
        let store = Arc::new(CapturingStore::default());
        let response = service(Arc::clone(&store))
            .receive(
                request(body()),
                OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        assert_eq!(
            response.map(|value| value.status),
            Ok(http::StatusCode::ACCEPTED)
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_verification_and_parsing_never_write_a_receipt() {
        let store = Arc::new(CapturingStore::default());
        let mut invalid_signature = request(body());
        invalid_signature.body = Bytes::from_static(b"mutated");
        assert_eq!(
            service(Arc::clone(&store))
                .receive(
                    invalid_signature,
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                )
                .await,
            Err(ReceiveError::Rejected)
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);

        let invalid_json = Bytes::from_static(b"not-json");
        assert_eq!(
            service(Arc::clone(&store))
                .receive(
                    request(invalid_json),
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                )
                .await,
            Err(ReceiveError::Rejected)
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn committed_duplicate_and_conflict_use_provider_specific_responses() {
        let store = Arc::new(CapturingStore::default());
        if let Ok(mut disposition) = store.disposition.lock() {
            *disposition = Some(ReceiveDisposition::Duplicate(ReceiptId::new()));
        }
        let duplicate = service(Arc::clone(&store))
            .receive(
                request(body()),
                OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        assert_eq!(
            duplicate.map(|value| value.status),
            Ok(http::StatusCode::ACCEPTED)
        );

        if let Ok(mut disposition) = store.disposition.lock() {
            *disposition = Some(ReceiveDisposition::Conflict);
        }
        let conflict = service(store)
            .receive(
                request(body()),
                OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        assert_eq!(
            conflict.map(|value| value.status),
            Ok(http::StatusCode::CONFLICT)
        );
    }
}
