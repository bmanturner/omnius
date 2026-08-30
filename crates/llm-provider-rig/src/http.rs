use std::{fmt, future::Future, sync::Arc};

use bytes::Bytes;
use omnius_outbound_http::{OutboundHttpClients, OutboundHttpError, PolicyClass, Url};
use rig_core::{
    http_client::{
        Error as HttpError, HttpClientExt, LazyBody, MultipartForm, Request, Response,
        StreamingResponse, sse::BoxedStream,
    },
    wasm_compat::WasmCompatSend,
};

tokio::task_local! {
    static RESPONSE_BODY_LIMIT: usize;
}

#[derive(Clone, Default)]
pub(crate) struct RigHttpClient {
    clients: Option<Arc<OutboundHttpClients>>,
}

impl RigHttpClient {
    pub(crate) fn new(clients: Arc<OutboundHttpClients>) -> Self {
        Self {
            clients: Some(clients),
        }
    }
}

impl fmt::Debug for RigHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RigHttpClient { .. }")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RigHttpFailure {
    ResponseTooLarge,
    Timeout,
    Rejected,
    Transport,
    Unsupported,
}

#[derive(Debug)]
struct RigTransportError {
    failure: RigHttpFailure,
}

impl fmt::Display for RigTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.failure {
            RigHttpFailure::ResponseTooLarge => "provider response exceeded its allowed size",
            RigHttpFailure::Timeout => "provider transport timed out",
            RigHttpFailure::Rejected => "provider transport request was rejected",
            RigHttpFailure::Transport => "provider transport failed",
            RigHttpFailure::Unsupported => "provider transport mode is unsupported",
        })
    }
}

impl std::error::Error for RigTransportError {}

pub(crate) async fn with_response_body_limit<F>(limit: Option<u64>, future: F) -> F::Output
where
    F: Future,
{
    let limit = limit
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(usize::MAX);
    RESPONSE_BODY_LIMIT.scope(limit, future).await
}

pub(crate) fn failure_from_http_error(error: &HttpError) -> Option<RigHttpFailure> {
    let HttpError::Instance(source) = error else {
        return None;
    };
    source
        .downcast_ref::<RigTransportError>()
        .map(|error| error.failure)
}

impl HttpClientExt for RigHttpClient {
    fn send<T, U>(
        &self,
        request: Request<T>,
    ) -> impl Future<Output = rig_core::http_client::Result<Response<LazyBody<U>>>>
    + WasmCompatSend
    + 'static
    where
        T: Into<Bytes> + WasmCompatSend,
        U: From<Bytes> + WasmCompatSend + 'static,
    {
        let clients = self.clients.clone();
        let (parts, body) = request.into_parts();
        let body: Bytes = body.into();
        async move {
            let clients = clients.ok_or_else(|| transport_error(RigHttpFailure::Rejected))?;
            let url = Url::parse(&parts.uri.to_string())
                .map_err(|_| transport_error(RigHttpFailure::Rejected))?;
            let approved = clients.approve(url).await.map_err(map_outbound_error)?;
            let request = clients
                .request(PolicyClass::NoRedirect, parts.method, &approved)
                .headers(parts.headers)
                .body(body)
                .build()
                .map_err(map_outbound_error)?;
            let limit = RESPONSE_BODY_LIMIT
                .try_with(|limit| *limit)
                .unwrap_or_else(|_| clients.response_body_limit_bytes());
            let response = clients
                .execute_bounded_with_limit(request, limit)
                .await
                .map_err(map_outbound_error)?;
            into_rig_response(response)
        }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "Rig requires a static multipart future that must not borrow the client"
    )]
    fn send_multipart<U>(
        &self,
        _request: Request<MultipartForm>,
    ) -> impl Future<Output = rig_core::http_client::Result<Response<LazyBody<U>>>>
    + WasmCompatSend
    + 'static
    where
        U: From<Bytes> + WasmCompatSend + 'static,
    {
        async { Err(transport_error(RigHttpFailure::Unsupported)) }
    }

    async fn send_streaming<T>(
        &self,
        request: Request<T>,
    ) -> rig_core::http_client::Result<StreamingResponse>
    where
        T: Into<Bytes> + WasmCompatSend,
    {
        let clients = self
            .clients
            .clone()
            .ok_or_else(|| transport_error(RigHttpFailure::Rejected))?;
        let (parts, body) = request.into_parts();
        let body: Bytes = body.into();
        let url = Url::parse(&parts.uri.to_string())
            .map_err(|_| transport_error(RigHttpFailure::Rejected))?;
        let approved = clients.approve(url).await.map_err(map_outbound_error)?;
        let request = clients
            .request(PolicyClass::NoRedirect, parts.method, &approved)
            .headers(parts.headers)
            .body(body)
            .build()
            .map_err(map_outbound_error)?;
        let limit = RESPONSE_BODY_LIMIT
            .try_with(|limit| *limit)
            .unwrap_or_else(|_| clients.response_body_limit_bytes());
        let response = clients
            .execute_streaming_with_limit(request, limit)
            .await
            .map_err(map_outbound_error)?;
        let (status, headers, mut body) = response.into_parts();
        if !status.is_success() {
            let mut bytes = Vec::new();
            while let Some(chunk) = body.next_chunk().await {
                bytes.extend_from_slice(&chunk.map_err(map_outbound_error)?);
            }
            return Err(HttpError::InvalidStatusCodeWithDetails {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
                headers: Box::new(headers),
            });
        }

        let stream: BoxedStream = Box::pin(futures::stream::unfold(body, |mut body| async move {
            body.next_chunk()
                .await
                .map(|chunk| (chunk.map(Bytes::from).map_err(map_outbound_error), body))
        }));
        let mut response = Response::builder().status(status);
        let response_headers = response.headers_mut().ok_or(HttpError::NoHeaders)?;
        *response_headers = headers;
        response.body(stream).map_err(HttpError::Protocol)
    }
}

fn into_rig_response<U>(
    response: omnius_outbound_http::BoundedResponse,
) -> rig_core::http_client::Result<Response<LazyBody<U>>>
where
    U: From<Bytes> + WasmCompatSend + 'static,
{
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body();
    if !status.is_success() {
        return Err(HttpError::InvalidStatusCodeWithDetails {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
            headers: Box::new(headers),
        });
    }

    let body: LazyBody<U> = Box::pin(async move { Ok(U::from(Bytes::from(body))) });
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().ok_or(HttpError::NoHeaders)?;
    *response_headers = headers;
    response.body(body).map_err(HttpError::Protocol)
}

fn map_outbound_error(error: OutboundHttpError) -> HttpError {
    let failure = match error {
        OutboundHttpError::ResponseTooLarge => RigHttpFailure::ResponseTooLarge,
        OutboundHttpError::Timeout => RigHttpFailure::Timeout,
        OutboundHttpError::Resolution
        | OutboundHttpError::Transport
        | OutboundHttpError::ResponseBody => RigHttpFailure::Transport,
        OutboundHttpError::RequestBuild
        | OutboundHttpError::DestinationRejected
        | OutboundHttpError::RedirectRejected
        | OutboundHttpError::RedirectLimit
        | OutboundHttpError::RedirectLoop
        | OutboundHttpError::NonReplayableRedirect
        | OutboundHttpError::InvalidResponseBodyLimit => RigHttpFailure::Rejected,
    };
    transport_error(failure)
}

fn transport_error(failure: RigHttpFailure) -> HttpError {
    HttpError::Instance(Box::new(RigTransportError { failure }))
}

#[cfg(test)]
pub(crate) fn error_for_test(failure: RigHttpFailure) -> HttpError {
    transport_error(failure)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc, time::Duration};

    use bytes::Bytes;
    use omnius_outbound_http::{
        OutboundHttpClients, OutboundHttpConfig, OutboundUrlPolicyConfig, ProxyPolicy,
    };
    use rig_core::http_client::{
        Error as HttpError, HttpClientExt, LazyBody, Request, Response,
        StreamingResponse as HttpStreamingResponse,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{RigHttpClient, RigHttpFailure, failure_from_http_error, with_response_body_limit};

    #[tokio::test]
    async fn bounded_transport_caps_body_and_preserves_error_metadata() -> Result<(), Box<dyn Error>>
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/completion"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 64]))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/provider-error"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "11")
                    .set_body_string(r#"{"error":{"code":"rate_limit_error"}}"#),
            )
            .mount(&server)
            .await;
        let config = OutboundHttpConfig {
            connect_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(2),
            response_body_limit_bytes: 128,
            max_redirects: 1,
            proxy: ProxyPolicy::Disabled,
            user_agent: "omnius-llm-provider-rig-test/1".to_owned(),
            url_policy: OutboundUrlPolicyConfig {
                allow_development_loopback_http: true,
                ..OutboundUrlPolicyConfig::default()
            },
        };
        let client = RigHttpClient::new(Arc::new(OutboundHttpClients::new(&config)?));
        let request = Request::post(format!("{}/completion", server.uri()))
            .body(Bytes::from_static(b"{}"))?;
        let result: rig_core::http_client::Result<Response<LazyBody<Vec<u8>>>> =
            with_response_body_limit(Some(8), client.send(request)).await;
        let Err(error) = result else {
            return Err("oversized response was accepted".into());
        };
        assert_eq!(
            failure_from_http_error(&error),
            Some(RigHttpFailure::ResponseTooLarge)
        );

        let request = Request::post(format!("{}/provider-error", server.uri()))
            .body(Bytes::from_static(b"{}"))?;
        let result: rig_core::http_client::Result<Response<LazyBody<Vec<u8>>>> =
            with_response_body_limit(Some(128), client.send(request)).await;
        let Err(HttpError::InvalidStatusCodeWithDetails {
            status,
            body,
            headers,
        }) = result
        else {
            return Err("provider error metadata was not preserved".into());
        };
        assert_eq!(status.as_u16(), 429);
        assert_eq!(
            headers
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("11")
        );
        assert_eq!(body, r#"{"error":{"code":"rate_limit_error"}}"#);

        let request = Request::post(format!("{}/provider-error", server.uri()))
            .body(Bytes::from_static(b"{}"))?;
        let result: rig_core::http_client::Result<HttpStreamingResponse> =
            with_response_body_limit(Some(128), client.send_streaming(request)).await;
        let Err(HttpError::InvalidStatusCodeWithDetails {
            status,
            body,
            headers,
        }) = result
        else {
            return Err("streaming provider error metadata was not preserved".into());
        };
        assert_eq!(status.as_u16(), 429);
        assert_eq!(
            headers
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("11")
        );
        assert_eq!(body, r#"{"error":{"code":"rate_limit_error"}}"#);
        Ok(())
    }

    #[tokio::test]
    async fn default_http_client_is_disabled_without_network_access() -> Result<(), Box<dyn Error>>
    {
        let request =
            Request::post("https://api.openai.com/v1/responses").body(Bytes::from_static(b"{}"))?;
        let result: rig_core::http_client::Result<Response<LazyBody<Vec<u8>>>> =
            RigHttpClient::default().send(request).await;
        let Err(error) = result else {
            return Err("disabled client unexpectedly sent a request".into());
        };
        assert_eq!(
            failure_from_http_error(&error),
            Some(RigHttpFailure::Rejected)
        );
        Ok(())
    }
}
