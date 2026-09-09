#[path = "request_bin_openapi.rs"]
mod request_bin_openapi;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, Request, State as AxumState},
    http::{
        HeaderMap, Method, StatusCode,
        header::{CACHE_CONTROL, CONTENT_LENGTH},
    },
    response::{IntoResponse as _, Response},
    routing::get,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use service_kit::{
    ApplicationExtension, Clock, ErrorCode, ExpectedOperation, RequestId, ServiceError,
    SystemClock, http::ProblemDetails,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const BINS_PATH: &str = "/bins";
const BIN_PATH: &str = "/bins/{bin_id}";
const CAPTURE_PATH: &str = "/capture/{bin_id}";
const DEFAULT_TTL_SECONDS: u64 = 3_600;
const MIN_TTL_SECONDS: u64 = 60;
const MAX_TTL_SECONDS: u64 = 86_400;
const MAX_LIVE_BINS: usize = 64;
const MAX_CAPTURES_PER_BIN: usize = 25;
const MAX_CAPTURE_BODY_BYTES: usize = 16 * 1_024;
const MAX_CAPTURE_HEADER_BYTES: usize = 16 * 1_024;
const TOKEN_BYTES: usize = 32;
const REDACTED_HEADER_VALUE: &str = "[REDACTED]";
const APPLICATION_ROUTES: &[&str] = &[BINS_PATH, BIN_PATH, CAPTURE_PATH];
const APPLICATION_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new("post", BINS_PATH, "createRequestBin", "request-bins"),
    ExpectedOperation::new("get", BIN_PATH, "inspectRequestBin", "request-bins"),
    ExpectedOperation::new("delete", BIN_PATH, "deleteRequestBin", "request-bins"),
    ExpectedOperation::new("get", CAPTURE_PATH, "captureRequestGet", "captures"),
    ExpectedOperation::new("head", CAPTURE_PATH, "captureRequestHead", "captures"),
    ExpectedOperation::new("post", CAPTURE_PATH, "captureRequestPost", "captures"),
    ExpectedOperation::new("put", CAPTURE_PATH, "captureRequestPut", "captures"),
    ExpectedOperation::new("patch", CAPTURE_PATH, "captureRequestPatch", "captures"),
    ExpectedOperation::new("delete", CAPTURE_PATH, "captureRequestDelete", "captures"),
    ExpectedOperation::new("options", CAPTURE_PATH, "captureRequestOptions", "captures"),
    ExpectedOperation::new("trace", CAPTURE_PATH, "captureRequestTrace", "captures"),
];

#[derive(Clone)]
struct ApplicationState {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn Clock>,
}

#[derive(Default)]
struct State {
    bins: HashMap<RequestId, RequestBin>,
}

struct RequestBin {
    token_digest: [u8; 32],
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    captures: VecDeque<Capture>,
}

#[derive(Clone, Serialize)]
struct Capture {
    #[serde(rename = "capture_id")]
    id: String,
    method: String,
    path: String,
    query: Option<String>,
    captured_at: String,
    headers: BTreeMap<String, Vec<String>>,
    body_base64: String,
}

/// Application-owned contribution boundary.
pub(crate) fn contributions(
    contributions: service_kit::ApplicationContributions,
) -> service_kit::ApplicationContributions {
    contributions
        .with_contract_document(request_bin_openapi::document)
        .with_application_extension(|_| Ok(extension_with_clock(Arc::new(SystemClock))))
}

pub(crate) fn default_extension() -> ApplicationExtension {
    extension_with_clock(Arc::new(SystemClock))
}

fn extension_with_clock(clock: Arc<dyn Clock>) -> ApplicationExtension {
    let state = ApplicationState {
        state: Arc::new(Mutex::new(State::default())),
        clock,
    };
    ApplicationExtension::new(
        application_router(state),
        APPLICATION_ROUTES,
        request_bin_openapi::document(),
        APPLICATION_OPERATIONS,
    )
}

fn application_router(state: ApplicationState) -> Router {
    Router::new()
        .route(BINS_PATH, axum::routing::post(create_request_bin))
        .route(
            BIN_PATH,
            get(inspect_request_bin).delete(delete_request_bin),
        )
        .route(
            CAPTURE_PATH,
            get(capture_request)
                .head(capture_request)
                .post(capture_request)
                .put(capture_request)
                .patch(capture_request)
                .delete(capture_request)
                .options(capture_request)
                .trace(capture_request)
                .fallback(unsupported_capture_method),
        )
        .with_state(state)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequestBinRequest {
    ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
struct CreateRequestBinResponse {
    bin_id: String,
    read_token: String,
    capture_path: String,
    inspect_path: String,
    created_at: String,
    expires_at: String,
}

#[derive(Serialize)]
struct InspectRequestBinResponse {
    bin_id: String,
    capture_path: String,
    inspect_path: String,
    created_at: String,
    expires_at: String,
    captures: Vec<Capture>,
}

#[derive(Serialize)]
struct CaptureAcceptedResponse {
    capture_id: String,
    captured_at: String,
}

async fn create_request_bin(
    AxumState(state): AxumState<ApplicationState>,
    request: Request,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(&request);
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| ApiError::invalid_json(request_id))?;
    let command = if body.is_empty() {
        CreateRequestBinRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid_json(request_id))?
    };
    let ttl_seconds = command.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(ApiError::invalid_ttl(request_id));
    }

    let now = state.clock.now_utc();
    let expires_at = now
        .checked_add(Duration::seconds(ttl_seconds.cast_signed()))
        .ok_or_else(|| ApiError::internal(request_id))?;
    let bin_id = RequestId::new();
    let (read_token, token_digest) = issue_read_token(request_id)?;
    let bin_id_text = bin_id.to_string();
    let capture_path = format!("/capture/{bin_id_text}");
    let inspect_path = format!("/bins/{bin_id_text}");
    let response = CreateRequestBinResponse {
        bin_id: bin_id_text,
        read_token,
        capture_path,
        inspect_path,
        created_at: format_timestamp(now, request_id)?,
        expires_at: format_timestamp(expires_at, request_id)?,
    };

    let mut bins = lock_state(&state, request_id)?;
    purge_expired(&mut bins, now);
    if bins.bins.len() >= MAX_LIVE_BINS {
        return Err(ApiError::bin_capacity_exceeded(request_id));
    }
    let std::collections::hash_map::Entry::Vacant(entry) = bins.bins.entry(bin_id) else {
        return Err(ApiError::internal(request_id));
    };
    entry.insert(RequestBin {
        token_digest,
        created_at: now,
        expires_at,
        captures: VecDeque::new(),
    });
    drop(bins);

    Ok(no_store_json(StatusCode::CREATED, response))
}

async fn inspect_request_bin(
    AxumState(state): AxumState<ApplicationState>,
    Path(bin_id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(&request);
    let provided_digest = bearer_digest(request.headers());
    let bin_id = parse_bin_id(&bin_id, request_id)?;
    let now = state.clock.now_utc();
    let mut bins = lock_state(&state, request_id)?;
    purge_expired(&mut bins, now);
    let bin = bins
        .bins
        .get(&bin_id)
        .ok_or_else(|| ApiError::bin_not_found(request_id))?;
    verify_token(bin, provided_digest.as_ref(), request_id)?;
    let bin_id_text = bin_id.to_string();
    let response = InspectRequestBinResponse {
        capture_path: format!("/capture/{bin_id_text}"),
        inspect_path: format!("/bins/{bin_id_text}"),
        bin_id: bin_id_text,
        created_at: format_timestamp(bin.created_at, request_id)?,
        expires_at: format_timestamp(bin.expires_at, request_id)?,
        captures: bin.captures.iter().cloned().collect(),
    };
    drop(bins);

    Ok(no_store_json(StatusCode::OK, response))
}

async fn delete_request_bin(
    AxumState(state): AxumState<ApplicationState>,
    Path(bin_id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(&request);
    let provided_digest = bearer_digest(request.headers());
    let bin_id = parse_bin_id(&bin_id, request_id)?;
    let now = state.clock.now_utc();
    let mut bins = lock_state(&state, request_id)?;
    purge_expired(&mut bins, now);
    let bin = bins
        .bins
        .get(&bin_id)
        .ok_or_else(|| ApiError::bin_not_found(request_id))?;
    verify_token(bin, provided_digest.as_ref(), request_id)?;
    bins.bins.remove(&bin_id);

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn capture_request(
    AxumState(state): AxumState<ApplicationState>,
    Path(bin_id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(&request);
    let bin_id = parse_bin_id(&bin_id, request_id)?;

    {
        let started_at = state.clock.now_utc();
        let mut bins = lock_state(&state, request_id)?;
        purge_expired(&mut bins, started_at);
        if !bins.bins.contains_key(&bin_id) {
            return Err(ApiError::bin_not_found(request_id));
        }
    }

    let (parts, body) = request.into_parts();
    validate_capture_header_bytes(&parts.headers, request_id)?;
    if declared_body_exceeds_limit(&parts.headers) {
        return Err(ApiError::capture_body_too_large(request_id));
    }
    let body = to_bytes(body, MAX_CAPTURE_BODY_BYTES)
        .await
        .map_err(|_| ApiError::capture_body_too_large(request_id))?;
    let headers = capture_headers(&parts.headers);
    let captured_at = state.clock.now_utc();
    let capture_id = RequestId::new().to_string();
    let captured_at_text = format_timestamp(captured_at, request_id)?;
    let capture = Capture {
        id: capture_id.clone(),
        method: parts.method.as_str().to_owned(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().map(str::to_owned),
        captured_at: captured_at_text.clone(),
        headers,
        body_base64: STANDARD.encode(body),
    };

    let mut bins = lock_state(&state, request_id)?;
    purge_expired(&mut bins, captured_at);
    let bin = bins
        .bins
        .get_mut(&bin_id)
        .ok_or_else(|| ApiError::bin_not_found(request_id))?;
    if bin.captures.len() == MAX_CAPTURES_PER_BIN {
        let _ = bin.captures.pop_front();
    }
    bin.captures.push_back(capture);
    drop(bins);

    if parts.method == Method::HEAD {
        Ok(StatusCode::ACCEPTED.into_response())
    } else {
        Ok((
            StatusCode::ACCEPTED,
            Json(CaptureAcceptedResponse {
                capture_id,
                captured_at: captured_at_text,
            }),
        )
            .into_response())
    }
}

async fn unsupported_capture_method(request: Request) -> ApiError {
    ApiError::method_not_allowed(resolve_request_id(&request))
}

fn validate_capture_header_bytes(
    headers: &HeaderMap,
    request_id: RequestId,
) -> Result<(), ApiError> {
    let mut total = 0_usize;
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .filter(|total| *total <= MAX_CAPTURE_HEADER_BYTES)
            .ok_or_else(|| ApiError::capture_headers_too_large(request_id))?;
    }
    Ok(())
}

fn declared_body_exceeds_limit(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_LENGTH).iter().any(|value| {
        value.as_bytes().split(|byte| *byte == b',').any(|value| {
            std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .is_some_and(|length| match usize::try_from(length) {
                    Ok(length) => length > MAX_CAPTURE_BODY_BYTES,
                    Err(_) => true,
                })
        })
    })
}

fn capture_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut captured = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        let value = if is_sensitive_header(name.as_str()) {
            REDACTED_HEADER_VALUE.to_owned()
        } else {
            value
                .to_str()
                .map_or_else(|_| "[NON_UTF8]".to_owned(), str::to_owned)
        };
        captured
            .entry(name.as_str().to_owned())
            .or_default()
            .push(value);
    }
    captured
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

fn issue_read_token(request_id: RequestId) -> Result<(String, [u8; 32]), ApiError> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ApiError::internal(request_id))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let digest = digest_token(&token);
    Ok((token, digest))
}

fn bearer_digest(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return None;
    }
    Some(digest_token(token))
}

fn digest_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn verify_token(
    bin: &RequestBin,
    provided_digest: Option<&[u8; 32]>,
    request_id: RequestId,
) -> Result<(), ApiError> {
    let missing_digest = [0_u8; 32];
    let candidate = provided_digest.unwrap_or(&missing_digest);
    let equal = bool::from(bin.token_digest.ct_eq(candidate));
    if provided_digest.is_some() && equal {
        Ok(())
    } else {
        Err(ApiError::bin_not_found(request_id))
    }
}

fn parse_bin_id(value: &str, request_id: RequestId) -> Result<RequestId, ApiError> {
    value
        .parse()
        .map_err(|_| ApiError::bin_not_found(request_id))
}

fn purge_expired(state: &mut State, now: OffsetDateTime) {
    state.bins.retain(|_, bin| bin.expires_at > now);
}

fn lock_state(
    state: &ApplicationState,
    request_id: RequestId,
) -> Result<std::sync::MutexGuard<'_, State>, ApiError> {
    state
        .state
        .lock()
        .map_err(|_| ApiError::internal(request_id))
}

fn format_timestamp(value: OffsetDateTime, request_id: RequestId) -> Result<String, ApiError> {
    value
        .format(&Rfc3339)
        .map_err(|_| ApiError::internal(request_id))
}

fn resolve_request_id(request: &Request) -> RequestId {
    request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new)
}

fn no_store_json<T: Serialize>(status: StatusCode, body: T) -> Response {
    (status, [(CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

#[derive(Clone, Copy, Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
}

impl ApiError {
    const fn new(
        status: StatusCode,
        code: &'static str,
        detail: &'static str,
        request_id: RequestId,
    ) -> Self {
        Self {
            status,
            code,
            detail,
            request_id,
        }
    }

    const fn invalid_json(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "INVALID_JSON",
            "request body must be valid JSON",
            request_id,
        )
    }

    const fn invalid_ttl(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_TTL_SECONDS",
            "ttl_seconds must be between 60 and 86400",
            request_id,
        )
    }

    const fn bin_not_found(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "BIN_NOT_FOUND",
            "request bin was not found",
            request_id,
        )
    }

    const fn bin_capacity_exceeded(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "BIN_CAPACITY_EXCEEDED",
            "the maximum number of live request bins has been reached",
            request_id,
        )
    }

    const fn capture_body_too_large(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "CAPTURE_BODY_TOO_LARGE",
            "capture body exceeds the 16384-byte limit",
            request_id,
        )
    }

    const fn capture_headers_too_large(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "CAPTURE_HEADERS_TOO_LARGE",
            "capture headers exceed the 16384-byte aggregate limit",
            request_id,
        )
    }

    const fn method_not_allowed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "CAPTURE_METHOD_NOT_ALLOWED",
            "capture method is not supported",
            request_id,
        )
    }

    const fn internal(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "an internal service error occurred",
            request_id,
        )
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let response = ErrorCode::try_new(self.code)
            .ok()
            .and_then(|code| {
                let service_error = ServiceError::new(code, self.detail);
                ProblemDetails::from_service_error(self.status, &service_error, self.request_id)
                    .ok()
            })
            .map_or_else(
                || StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                axum::response::IntoResponse::into_response,
            );
        let mut response = response;
        response.headers_mut().insert(
            CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response
    }
}

#[cfg(test)]
#[path = "application_tests.rs"]
mod tests;
