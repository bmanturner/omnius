use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequestParts, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE, request::Parts},
    response::{IntoResponse as _, Response},
    routing::post,
};
use time::OffsetDateTime;

use crate::{InboundWebhookService, ProviderResponse, RawWebhookRequest, ReceiveError};

/// Builds the provider-authenticated callback route with its own exact body limit.
///
/// The returned router intentionally has no browser authentication or CSRF layer. Mount it with
/// `HttpShell::apply_machine_callbacks` so it retains the shared transport protections.
pub fn webhook_router(service: InboundWebhookService) -> Router {
    let body_limit = service.max_body_bytes();
    Router::new()
        .route("/webhooks/inbound/{provider}", post(receive_webhook))
        .with_state(service)
        .layer(DefaultBodyLimit::max(body_limit))
}

struct BoundedHeaders(HeaderMap);

impl FromRequestParts<InboundWebhookService> for BoundedHeaders {
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut Parts,
        service: &InboundWebhookService,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(if service.headers_within(&parts.headers) {
            Ok(Self(std::mem::take(&mut parts.headers)))
        } else {
            Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
        })
    }
}

async fn receive_webhook(
    Path(provider): Path<String>,
    State(service): State<InboundWebhookService>,
    BoundedHeaders(headers): BoundedHeaders,
    body: Bytes,
) -> Response {
    match service
        .receive(
            RawWebhookRequest {
                provider,
                headers,
                body,
            },
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(response) => provider_response(response),
        Err(error) => receive_error(error),
    }
}

fn provider_response(response: ProviderResponse) -> Response {
    let mut result = (response.status, response.body).into_response();
    if let Some(content_type) = response.content_type
        && let Ok(value) = HeaderValue::from_str(content_type)
    {
        result.headers_mut().insert(CONTENT_TYPE, value);
    }
    result
}

fn receive_error(error: ReceiveError) -> Response {
    let status = match error {
        ReceiveError::LimitExceeded => StatusCode::PAYLOAD_TOO_LARGE,
        ReceiveError::UnknownProvider => StatusCode::NOT_FOUND,
        ReceiveError::Rejected => StatusCode::BAD_REQUEST,
        ReceiveError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    status.into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{body::Body, http::Request};
    use futures::future::BoxFuture;
    use http::{HeaderValue, header::ORIGIN};
    use omnius_config::SecretString;
    use omnius_http::{HttpShell, HttpShellConfig, REQUEST_ID_HEADER};
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        FixtureHmacProviderConfig, NewReceipt, ProcessorConfig, ReceiptRepository,
        ReceiptStoreError, ReceiveDisposition, ReceiveLimits, WebhookConfig, sign_fixture_request,
    };

    const SECRET: &str = "fixture-secret-material-with-at-least-thirty-two-bytes";

    struct AcceptingStore;

    impl ReceiptRepository for AcceptingStore {
        fn receive<'a>(
            &'a self,
            receipt: &'a NewReceipt,
        ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>> {
            Box::pin(async move { Ok(ReceiveDisposition::Accepted(receipt.id())) })
        }
    }

    struct SlowStore;

    impl ReceiptRepository for SlowStore {
        fn receive<'a>(
            &'a self,
            receipt: &'a NewReceipt,
        ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok(ReceiveDisposition::Accepted(receipt.id()))
            })
        }
    }

    #[derive(Default)]
    struct ConcurrencyTracker {
        active: AtomicUsize,
        maximum: AtomicUsize,
    }

    impl ConcurrencyTracker {
        fn enter(&self) {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
        }

        fn leave(&self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct ConcurrencyStore {
        tracker: Arc<ConcurrencyTracker>,
    }

    impl ReceiptRepository for ConcurrencyStore {
        fn receive<'a>(
            &'a self,
            receipt: &'a NewReceipt,
        ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>> {
            Box::pin(async move {
                self.tracker.enter();
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.tracker.leave();
                Ok(ReceiveDisposition::Accepted(receipt.id()))
            })
        }
    }

    struct PanickingStore;

    impl ReceiptRepository for PanickingStore {
        fn receive<'a>(
            &'a self,
            _receipt: &'a NewReceipt,
        ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>> {
            Box::pin(async move {
                panic!("machine callback handler panic");
            })
        }
    }

    fn app(body_limit: usize, header_count: usize) -> Router {
        app_with_store(body_limit, header_count, Arc::new(AcceptingStore))
    }

    fn app_with_store(
        body_limit: usize,
        header_count: usize,
        receipts: Arc<dyn ReceiptRepository>,
    ) -> Router {
        let config = WebhookConfig {
            enabled: true,
            max_body_bytes: body_limit,
            max_header_count: header_count,
            max_header_bytes: 4_096,
            max_safe_payload_bytes: body_limit.min(2_048),
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
        let service = InboundWebhookService::new(
            config.build_registry().unwrap_or_else(|_| unreachable!()),
            receipts,
            ReceiveLimits {
                max_body_bytes: body_limit,
                max_header_count: header_count,
                max_header_bytes: 4_096,
                max_safe_payload_bytes: body_limit.min(2_048),
            },
            Duration::from_hours(720),
        )
        .unwrap_or_else(|_| unreachable!());
        webhook_router(service)
    }

    fn signed_request(body: &'static [u8]) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let signature = sign_fixture_request(
            SECRET.as_bytes(),
            "fixture",
            timestamp,
            "tenant/one",
            "evt_1",
            body,
        )?;
        let mut request = Request::post("/webhooks/inbound/fixture").body(Body::from(body))?;
        let headers = request.headers_mut();
        headers.insert("x-fixture-signature", HeaderValue::from_str(&signature)?);
        headers.insert(
            "x-fixture-timestamp",
            HeaderValue::from_str(&timestamp.to_string())?,
        );
        headers.insert("x-fixture-scope", HeaderValue::from_static("tenant/one"));
        headers.insert("x-fixture-event-id", HeaderValue::from_static("evt_1"));
        Ok(request)
    }

    #[tokio::test]
    async fn route_rejects_oversized_body_before_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app(64, 16)
            .oneshot(Request::post("/webhooks/inbound/fixture").body(Body::from(vec![b'x'; 65]))?)
            .await?;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    #[tokio::test]
    async fn route_rejects_excess_headers_before_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut request = signed_request(br#"{"version":1,"type":"invoice.paid","data":{}}"#)?;
        let headers = request.headers_mut();
        headers.insert("x-extra", HeaderValue::from_static("bounded"));
        let response = app(1_024, 4).oneshot(request).await?;
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        Ok(())
    }

    #[tokio::test]
    async fn cross_site_callback_uses_shared_machine_transport_protections()
    -> Result<(), Box<dyn std::error::Error>> {
        const BODY: &[u8] = br#"{"version":1,"type":"invoice.paid","data":{}}"#;
        let shell = HttpShell::new(HttpShellConfig {
            max_body_bytes: 1_024,
            max_header_bytes: 512,
            max_header_count: 16,
            max_in_flight: 1,
            handler_timeout: Duration::from_millis(50),
            ..HttpShellConfig::default()
        })?;
        let protected = shell.apply_machine_callbacks(app(64, 16));
        let mut cross_site = signed_request(BODY)?;
        cross_site
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        cross_site
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let accepted = protected.clone().oneshot(cross_site).await?;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        assert!(accepted.headers().contains_key(REQUEST_ID_HEADER));

        let mut oversized_headers = signed_request(BODY)?;
        oversized_headers
            .headers_mut()
            .insert("x-large", HeaderValue::from_str(&"a".repeat(600))?);
        let header_rejection = protected.clone().oneshot(oversized_headers).await?;
        assert_eq!(
            header_rejection.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );

        let body_rejection = protected
            .oneshot(Request::post("/webhooks/inbound/fixture").body(Body::from(vec![b'x'; 65]))?)
            .await?;
        assert_eq!(body_rejection.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let tracker = Arc::new(ConcurrencyTracker::default());
        let callback_store: Arc<dyn ReceiptRepository> = Arc::new(ConcurrencyStore {
            tracker: Arc::clone(&tracker),
        });
        let browser_tracker = Arc::clone(&tracker);
        let browser = Router::new().route(
            "/browser",
            axum::routing::get(move || {
                let tracker = Arc::clone(&browser_tracker);
                async move {
                    tracker.enter();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    tracker.leave();
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let browser = shell.apply(browser)?;
        let callbacks = shell.apply_machine_callbacks(app_with_store(1_024, 16, callback_store));
        let shared = browser.merge(callbacks);
        let (browser_response, callback_response) = tokio::join!(
            shared
                .clone()
                .oneshot(Request::get("/browser").body(Body::empty())?),
            shared.oneshot(signed_request(BODY)?),
        );
        let statuses = [browser_response?.status(), callback_response?.status()];
        assert!(statuses.contains(&StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status != StatusCode::SERVICE_UNAVAILABLE)
                .count(),
            1
        );
        assert_eq!(tracker.maximum.load(Ordering::SeqCst), 1);

        let deadline = HttpShell::new(HttpShellConfig {
            handler_timeout: Duration::from_millis(5),
            ..HttpShellConfig::default()
        })?
        .apply_machine_callbacks(app_with_store(1_024, 16, Arc::new(SlowStore)))
        .oneshot(signed_request(BODY)?)
        .await?;
        assert_eq!(deadline.status(), StatusCode::REQUEST_TIMEOUT);

        let panic_response = HttpShell::new(HttpShellConfig::default())?
            .apply_machine_callbacks(app_with_store(1_024, 16, Arc::new(PanickingStore)))
            .oneshot(signed_request(BODY)?)
            .await?;
        assert_eq!(panic_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(panic_response.headers().contains_key(REQUEST_ID_HEADER));
        Ok(())
    }
}
