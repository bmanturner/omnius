use std::{
    collections::BTreeSet,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Method, Request, Response, StatusCode, header::CACHE_CONTROL},
};
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt as _;
use serde::Deserialize;
use serde_json::{Value, json};
use service_kit::test_support::TestClock;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, Deserialize)]
struct CreatedBin {
    bin_id: String,
    read_token: String,
    capture_path: String,
    inspect_path: String,
}

fn fixed_clock() -> TestResult<TestClock> {
    Ok(TestClock::at(OffsetDateTime::from_unix_timestamp(
        1_800_000_000,
    )?))
}

fn router_with_clock(clock: &TestClock) -> Router {
    application_router(ApplicationState {
        state: Arc::new(Mutex::new(State::default())),
        clock: Arc::new(clock.clone()),
    })
}

fn request(method: Method, uri: &str, body: impl Into<Body>) -> TestResult<Request<Body>> {
    Ok(Request::builder()
        .method(method)
        .uri(uri)
        .body(body.into())?)
}

fn request_with_headers(
    method: Method,
    uri: &str,
    body: impl Into<Body>,
    headers: &[(&str, &str)],
) -> TestResult<Request<Body>> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    Ok(builder.body(body.into())?)
}

async fn send(router: &Router, request: Request<Body>) -> TestResult<Response<Body>> {
    Ok(router.clone().oneshot(request).await?)
}

async fn body_bytes(response: Response<Body>) -> TestResult<Vec<u8>> {
    Ok(response.into_body().collect().await?.to_bytes().to_vec())
}

async fn json_body(response: Response<Body>) -> TestResult<Value> {
    Ok(serde_json::from_slice(&body_bytes(response).await?)?)
}

async fn create_bin(router: &Router, ttl_seconds: u64) -> TestResult<CreatedBin> {
    let response = send(
        router,
        request(
            Method::POST,
            BINS_PATH,
            Body::from(json!({"ttl_seconds": ttl_seconds}).to_string()),
        )?,
    )
    .await?;
    if response.status() != StatusCode::CREATED {
        return Err(format!("create returned {}", response.status()).into());
    }
    Ok(serde_json::from_slice(&body_bytes(response).await?)?)
}

async fn inspect(router: &Router, bin: &CreatedBin) -> TestResult<Response<Body>> {
    send(
        router,
        request_with_headers(
            Method::GET,
            &bin.inspect_path,
            Body::empty(),
            &[("authorization", &format!("Bearer {}", bin.read_token))],
        )?,
    )
    .await
}

fn captures(document: &Value) -> TestResult<&[Value]> {
    document["captures"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| "inspect response did not contain a captures array".into())
}

async fn assert_problem(
    response: Response<Body>,
    status: StatusCode,
    code: &str,
) -> TestResult<Value> {
    if response.status() != status {
        return Err(format!("expected {status}, received {}", response.status()).into());
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with("application/problem+json") {
        return Err(format!("unexpected problem content type {content_type:?}").into());
    }
    let document = json_body(response).await?;
    assert_eq!(document["status"], u64::from(status.as_u16()));
    assert_eq!(document["code"], code);
    Ok(document)
}

#[tokio::test]
async fn create_capture_inspect_and_delete_preserve_binary_metadata_and_redact_secrets()
-> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, 3_600).await?;
    let binary = vec![0, 1, 2, 127, 128, 254, 255];
    let response = send(
        &router,
        request_with_headers(
            Method::POST,
            &format!("{}?source=unit%20test", bin.capture_path),
            Body::from(binary.clone()),
            &[
                ("x-visible", "retained"),
                ("authorization", "Bearer capture-secret"),
                ("proxy-authorization", "Basic proxy-secret"),
                ("cookie", "session=secret"),
                ("set-cookie", "session=secret"),
            ],
        )?,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let inspected = json_body(inspect(&router, &bin).await?).await?;
    let retained = captures(&inspected)?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0]["method"], "POST");
    assert_eq!(retained[0]["path"], bin.capture_path);
    assert_eq!(retained[0]["query"], "source=unit%20test");
    assert_eq!(retained[0]["body_base64"], STANDARD.encode(binary));
    assert_eq!(retained[0]["headers"]["x-visible"], json!(["retained"]));
    for sensitive in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    ] {
        assert_eq!(
            retained[0]["headers"][sensitive],
            json!([REDACTED_HEADER_VALUE]),
            "{sensitive} was not redacted"
        );
    }

    let deleted = send(
        &router,
        request_with_headers(
            Method::DELETE,
            &bin.inspect_path,
            Body::empty(),
            &[("authorization", &format!("Bearer {}", bin.read_token))],
        )?,
    )
    .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(body_bytes(deleted).await?.is_empty());
    let missing = inspect(&router, &bin).await?;
    assert_problem(missing, StatusCode::NOT_FOUND, "BIN_NOT_FOUND").await?;
    Ok(())
}

#[tokio::test]
async fn every_documented_capture_method_is_accepted_and_connect_is_rejected_without_storage()
-> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, 3_600).await?;
    let methods = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
        Method::TRACE,
    ];
    for method in &methods {
        let response = send(
            &router,
            request(
                method.clone(),
                &bin.capture_path,
                Body::from(method.as_str().to_owned()),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{method}");
        let response_body = body_bytes(response).await?;
        if *method == Method::HEAD {
            assert!(response_body.is_empty(), "HEAD returned a response body");
        } else {
            assert!(
                !response_body.is_empty(),
                "{method} omitted its acceptance body"
            );
        }
    }

    let connected = send(
        &router,
        request(Method::CONNECT, &bin.capture_path, Body::empty())?,
    )
    .await?;
    assert_problem(
        connected,
        StatusCode::METHOD_NOT_ALLOWED,
        "CAPTURE_METHOD_NOT_ALLOWED",
    )
    .await?;

    let inspected = json_body(inspect(&router, &bin).await?).await?;
    let retained_methods = captures(&inspected)?
        .iter()
        .map(|capture| capture["method"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        retained_methods,
        methods.iter().map(Method::as_str).collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
async fn create_rejects_malformed_json_and_ttl_values_outside_both_inclusive_bounds() -> TestResult
{
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let malformed = send(&router, request(Method::POST, BINS_PATH, Body::from("{"))?).await?;
    assert_problem(malformed, StatusCode::BAD_REQUEST, "INVALID_JSON").await?;

    for ttl in [MIN_TTL_SECONDS - 1, MAX_TTL_SECONDS + 1] {
        let response = send(
            &router,
            request(
                Method::POST,
                BINS_PATH,
                Body::from(json!({"ttl_seconds": ttl}).to_string()),
            )?,
        )
        .await?;
        assert_problem(
            response,
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_TTL_SECONDS",
        )
        .await?;
    }
    assert_eq!(
        send(
            &router,
            request(
                Method::POST,
                BINS_PATH,
                Body::from(json!({"ttl_seconds": MIN_TTL_SECONDS}).to_string()),
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        send(
            &router,
            request(
                Method::POST,
                BINS_PATH,
                Body::from(json!({"ttl_seconds": MAX_TTL_SECONDS}).to_string()),
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    Ok(())
}

#[tokio::test]
async fn successful_access_never_extends_the_fixed_ttl() -> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, MIN_TTL_SECONDS).await?;

    clock.advance(Duration::seconds(59))?;
    assert_eq!(inspect(&router, &bin).await?.status(), StatusCode::OK);
    clock.advance(Duration::seconds(1))?;
    let expired = inspect(&router, &bin).await?;
    assert_problem(expired, StatusCode::NOT_FOUND, "BIN_NOT_FOUND").await?;
    Ok(())
}

#[tokio::test]
async fn missing_wrong_unknown_and_expired_credentials_are_indistinguishable_no_store_problems()
-> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, MIN_TTL_SECONDS).await?;
    let unknown_path = format!("/bins/{}", RequestId::new());

    let missing = send(
        &router,
        request(Method::GET, &bin.inspect_path, Body::empty())?,
    )
    .await?;
    let wrong = send(
        &router,
        request_with_headers(
            Method::GET,
            &bin.inspect_path,
            Body::empty(),
            &[("authorization", "Bearer wrong")],
        )?,
    )
    .await?;
    let unknown = send(
        &router,
        request_with_headers(
            Method::GET,
            &unknown_path,
            Body::empty(),
            &[("authorization", "Bearer wrong")],
        )?,
    )
    .await?;
    clock.advance(Duration::seconds(60))?;
    let expired = inspect(&router, &bin).await?;

    let mut fingerprints = Vec::new();
    for response in [missing, wrong, unknown, expired] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let mut problem = assert_problem(response, StatusCode::NOT_FOUND, "BIN_NOT_FOUND").await?;
        let request_id = problem
            .as_object_mut()
            .and_then(|object| object.remove("request_id"));
        assert!(request_id.is_some());
        fingerprints.push(problem);
    }
    assert!(fingerprints.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[tokio::test]
async fn body_limit_accepts_exactly_sixteen_kib_and_rejects_one_more_without_partial_capture()
-> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, 3_600).await?;

    let accepted_body = vec![0xA5; MAX_CAPTURE_BODY_BYTES];
    let accepted = send(
        &router,
        request(
            Method::POST,
            &bin.capture_path,
            Body::from(accepted_body.clone()),
        )?,
    )
    .await?;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let rejected = send(
        &router,
        request(
            Method::POST,
            &bin.capture_path,
            Body::from(vec![0x5A; MAX_CAPTURE_BODY_BYTES + 1]),
        )?,
    )
    .await?;
    assert_problem(
        rejected,
        StatusCode::PAYLOAD_TOO_LARGE,
        "CAPTURE_BODY_TOO_LARGE",
    )
    .await?;

    let inspected = json_body(inspect(&router, &bin).await?).await?;
    let retained = captures(&inspected)?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0]["body_base64"], STANDARD.encode(accepted_body));
    Ok(())
}

#[tokio::test]
async fn header_limit_accepts_exactly_sixteen_kib_and_rejects_one_more_without_partial_capture()
-> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, 3_600).await?;
    let name = "x-limit";
    let exact_value = "a".repeat(MAX_CAPTURE_HEADER_BYTES - name.len());
    let over_value = "b".repeat(MAX_CAPTURE_HEADER_BYTES - name.len() + 1);

    let mut exact = request(Method::POST, &bin.capture_path, Body::empty())?;
    exact
        .headers_mut()
        .insert(name, HeaderValue::from_str(&exact_value)?);
    assert_eq!(send(&router, exact).await?.status(), StatusCode::ACCEPTED);

    let mut over = request(Method::POST, &bin.capture_path, Body::empty())?;
    over.headers_mut()
        .insert(name, HeaderValue::from_str(&over_value)?);
    let rejected = send(&router, over).await?;
    assert_problem(
        rejected,
        StatusCode::PAYLOAD_TOO_LARGE,
        "CAPTURE_HEADERS_TOO_LARGE",
    )
    .await?;

    let inspected = json_body(inspect(&router, &bin).await?).await?;
    let retained = captures(&inspected)?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0]["headers"][name][0], exact_value);
    Ok(())
}

#[tokio::test]
async fn sixty_four_live_bins_exhaust_capacity_and_expiry_reclaims_every_slot() -> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    for _ in 0..MAX_LIVE_BINS {
        let created = create_bin(&router, MIN_TTL_SECONDS).await?;
        assert!(!created.bin_id.is_empty());
    }
    let full = send(&router, request(Method::POST, BINS_PATH, Body::empty())?).await?;
    assert_problem(
        full,
        StatusCode::SERVICE_UNAVAILABLE,
        "BIN_CAPACITY_EXCEEDED",
    )
    .await?;

    clock.advance(Duration::seconds(60))?;
    assert_eq!(
        send(&router, request(Method::POST, BINS_PATH, Body::empty())?)
            .await?
            .status(),
        StatusCode::CREATED
    );
    Ok(())
}

#[tokio::test]
async fn capture_ring_retains_only_the_newest_twenty_five_in_oldest_first_order() -> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, 3_600).await?;
    for sequence in 0..30 {
        let response = send(
            &router,
            request(
                Method::POST,
                &bin.capture_path,
                Body::from(sequence.to_string()),
            )?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let inspected = json_body(inspect(&router, &bin).await?).await?;
    let retained = captures(&inspected)?;
    assert_eq!(retained.len(), MAX_CAPTURES_PER_BIN);
    let bodies = retained
        .iter()
        .map(|capture| capture["body_base64"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    let expected = (5..30)
        .map(|sequence| STANDARD.encode(sequence.to_string()))
        .collect::<Vec<_>>();
    assert_eq!(bodies, expected);
    Ok(())
}

#[tokio::test]
async fn concurrent_captures_remain_unique_uncorrupted_and_bounded() -> TestResult {
    let clock = fixed_clock()?;
    let router = router_with_clock(&clock);
    let bin = create_bin(&router, 3_600).await?;
    let mut tasks = Vec::new();
    for sequence in 0..40_u8 {
        let task_router = router.clone();
        let path = bin.capture_path.clone();
        let request = request(Method::POST, &path, Body::from(vec![sequence]))?;
        tasks.push(tokio::spawn(
            async move { task_router.oneshot(request).await },
        ));
    }
    for task in tasks {
        assert_eq!(task.await??.status(), StatusCode::ACCEPTED);
    }

    let inspected = json_body(inspect(&router, &bin).await?).await?;
    let retained = captures(&inspected)?;
    assert_eq!(retained.len(), MAX_CAPTURES_PER_BIN);
    let ids = retained
        .iter()
        .filter_map(|capture| capture["capture_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), MAX_CAPTURES_PER_BIN);
    let decoded = retained
        .iter()
        .map(|capture| {
            let encoded = capture["body_base64"].as_str().unwrap_or_default();
            STANDARD.decode(encoded)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(decoded.iter().all(|body| body.len() == 1 && body[0] < 40));
    assert_eq!(
        decoded.iter().collect::<BTreeSet<_>>().len(),
        MAX_CAPTURES_PER_BIN
    );
    Ok(())
}

#[test]
fn openapi_operations_exactly_match_expected_operations_and_security_boundaries() -> TestResult {
    let document = request_bin_openapi::document();
    let paths = document["paths"]
        .as_object()
        .ok_or("OpenAPI paths must be an object")?;
    let mut actual = BTreeSet::new();
    for (path, item) in paths {
        let operations = item
            .as_object()
            .ok_or("OpenAPI path item must be an object")?;
        for (method, operation) in operations {
            let operation_id = operation["operationId"]
                .as_str()
                .ok_or("OpenAPI operation must have an operationId")?;
            let tag = operation["tags"][0]
                .as_str()
                .ok_or("OpenAPI operation must have one ownership tag")?;
            actual.insert((method.as_str(), path.as_str(), operation_id, tag));
        }
    }
    let expected = APPLICATION_OPERATIONS
        .iter()
        .map(|operation| {
            (
                operation.method,
                operation.path,
                operation.operation_id,
                operation.tag,
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(document["paths"][BINS_PATH]["post"]["security"], json!([]));
    for method in [
        "get", "head", "post", "put", "patch", "delete", "options", "trace",
    ] {
        assert_eq!(
            document["paths"][CAPTURE_PATH][method]["security"],
            json!([])
        );
    }
    for method in ["get", "delete"] {
        assert_eq!(
            document["paths"][BIN_PATH][method]["security"],
            json!([{"binReadToken": []}])
        );
    }
    assert_eq!(
        document["components"]["securitySchemes"]["binReadToken"]["scheme"],
        "bearer"
    );
    Ok(())
}

#[tokio::test]
async fn composed_router_rate_limit_returns_quota_headers_and_rfc9457_problem() -> TestResult {
    let router = crate::router().await?;
    let peer = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41_000));
    let mut first = request(Method::POST, BINS_PATH, Body::empty())?;
    first.extensions_mut().insert(peer);
    assert_eq!(send(&router, first).await?.status(), StatusCode::CREATED);

    let mut second = request(Method::POST, BINS_PATH, Body::empty())?;
    second.extensions_mut().insert(peer);
    let denied = send(&router, second).await?;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    for name in [
        "retry-after",
        "x-ratelimit-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
    ] {
        assert!(denied.headers().contains_key(name), "missing {name}");
    }
    let problem = assert_problem(denied, StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").await?;
    assert_eq!(
        problem["type"],
        "https://errors.omnius.invalid/rate_limited"
    );
    assert_eq!(problem["title"], "Too Many Requests");
    Ok(())
}

#[tokio::test]
async fn constructing_a_fresh_router_loses_all_previous_process_state() -> TestResult {
    let clock = fixed_clock()?;
    let original = router_with_clock(&clock);
    let bin = create_bin(&original, 3_600).await?;
    assert_eq!(inspect(&original, &bin).await?.status(), StatusCode::OK);

    let restarted = router_with_clock(&clock);
    let absent = inspect(&restarted, &bin).await?;
    assert_problem(absent, StatusCode::NOT_FOUND, "BIN_NOT_FOUND").await?;
    Ok(())
}
