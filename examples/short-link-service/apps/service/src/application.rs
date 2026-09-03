use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
    response::{IntoResponse as _, Response},
    routing::{delete, get},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use service_kit::{
    ApplicationExtension, ErrorCode, ExpectedOperation, RequestId, ServiceError,
    http::ProblemDetails,
    idempotency::{
        ClaimOutcome, IdempotencyKey, IdempotencyOperation, IdempotencyRequest, IdempotencyScope,
        IdempotencyStoreError, PostgresIdempotencyStore, RequestFingerprint, SafeResponse,
    },
    postgres::{
        PostgresPool,
        sqlx::{self, Connection as _, PgConnection},
    },
};

const LINKS_PATH: &str = "/links";
const LINK_PATH: &str = "/links/{code}";
const REDIRECT_PATH: &str = "/r/{code}";
const CREATE_OPERATION: &str = "short-links.create";
const CREATE_FINGERPRINT_PREFIX: &[u8] = b"short-links.create\0";
const JSON_CONTENT_TYPE: &str = "application/json";
const MAX_TARGET_URL_BYTES: usize = 2_048;
const SHORT_CODE_LENGTH: usize = 12;
const MAX_CODE_ATTEMPTS: usize = 5;

const APPLICATION_ROUTES: &[&str] = &[LINKS_PATH, LINK_PATH, REDIRECT_PATH];
const APPLICATION_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new("post", LINKS_PATH, "createShortLink", "short-links"),
    ExpectedOperation::new("get", LINKS_PATH, "listShortLinks", "short-links"),
    ExpectedOperation::new("delete", LINK_PATH, "expireShortLink", "short-links"),
    ExpectedOperation::new("get", REDIRECT_PATH, "resolveShortLink", "short-links"),
];

#[derive(Clone)]
struct ApplicationState {
    pool: PostgresPool,
    idempotency_store: PostgresIdempotencyStore,
}

/// Application-owned contribution boundary.
pub(crate) fn contributions(
    contributions: service_kit::ApplicationContributions,
) -> service_kit::ApplicationContributions {
    contributions.with_application_extension(|runtime| {
        let state = ApplicationState {
            pool: runtime.postgres_pool()?,
            idempotency_store: runtime.idempotency_store()?,
        };
        Ok(ApplicationExtension::new(
            application_router(state),
            APPLICATION_ROUTES,
            openapi_document(),
            APPLICATION_OPERATIONS,
        ))
    })
}

// The generated composition root constructs this fallback before the
// application contribution replaces it.
pub(crate) fn default_extension() -> ApplicationExtension {
    ApplicationExtension::new(
        Router::new().route("/example", get(example)),
        &["/example"],
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "short-link-service",
                "version": env!("CARGO_PKG_VERSION")
            },
            "paths": {}
        }),
        &[],
    )
}

#[derive(Serialize)]
pub(crate) struct ExampleResponse {
    message: &'static str,
}

pub(crate) async fn example() -> Json<ExampleResponse> {
    Json(ExampleResponse {
        message: "hello from short-link-service",
    })
}

fn application_router(state: ApplicationState) -> Router {
    Router::new()
        .route(LINKS_PATH, get(list_short_links).post(create_short_link))
        .route(LINK_PATH, delete(expire_short_link))
        .route(REDIRECT_PATH, get(resolve_short_link))
        .with_state(state)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateShortLinkRequest {
    url: String,
}

#[derive(Deserialize, Serialize)]
struct CreateShortLinkResponse {
    code: String,
    url: String,
    redirect_path: String,
}

#[derive(Deserialize, Serialize)]
struct ShortLinkSummary {
    code: String,
    url: String,
    expired: bool,
}

#[derive(Deserialize, Serialize)]
struct ListShortLinksResponse {
    links: Vec<ShortLinkSummary>,
}

async fn create_short_link(
    State(state): State<ApplicationState>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    payload: Result<Json<CreateShortLinkRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let key = required_single_header(&headers, "idempotency-key").map_err(|()| {
        ApiError::bad_request(
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key must contain one valid value",
            request_id,
        )
    })?;
    let key = IdempotencyKey::try_from(key).map_err(|_| {
        ApiError::bad_request(
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key must contain one valid value",
            request_id,
        )
    })?;
    let Json(command) = payload.map_err(|error| map_json_rejection(&error, request_id))?;
    validate_target_url(&command.url).map_err(|()| {
        ApiError::unprocessable(
            "INVALID_TARGET_URL",
            "url must be an absolute HTTP or HTTPS URI without credentials",
            request_id,
        )
    })?;
    let identity = create_identity(key, &command, request_id)?;

    create_short_link_with(&state, &identity, command, request_id, next_short_code).await
}

async fn create_short_link_with<F>(
    state: &ApplicationState,
    identity: &IdempotencyRequest,
    command: CreateShortLinkRequest,
    request_id: RequestId,
    mut next_code: F,
) -> Result<Response, ApiError>
where
    F: FnMut() -> String + Send,
{
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let result = create_in_transaction(
        state.idempotency_store,
        &mut transaction,
        identity,
        command,
        request_id,
        &mut next_code,
    )
    .await;
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            if transaction.rollback().await.is_err() {
                return Err(ApiError::database_unavailable(request_id));
            }
            return Err(error);
        }
    };
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;

    match outcome {
        CreateTransactionOutcome::Started(body) => {
            Ok(json_bytes_response(StatusCode::CREATED, body))
        }
        CreateTransactionOutcome::Replay(response) => replay_response(&response, request_id),
        CreateTransactionOutcome::InProgress => Err(ApiError::conflict(
            "IDEMPOTENCY_IN_PROGRESS",
            "an equivalent request is still in progress",
            request_id,
        )),
    }
}

async fn create_in_transaction<F>(
    idempotency_store: PostgresIdempotencyStore,
    connection: &mut PgConnection,
    identity: &IdempotencyRequest,
    command: CreateShortLinkRequest,
    request_id: RequestId,
    next_code: &mut F,
) -> Result<CreateTransactionOutcome, ApiError>
where
    F: FnMut() -> String,
{
    match idempotency_store
        .claim_with(connection, identity)
        .await
        .map_err(|error| map_idempotency_error(error, request_id))?
    {
        ClaimOutcome::Replay(response) => Ok(CreateTransactionOutcome::Replay(response)),
        ClaimOutcome::InProgress => Ok(CreateTransactionOutcome::InProgress),
        ClaimOutcome::Started => {
            let code = insert_with_bounded_collision_retry(
                connection,
                &command.url,
                request_id,
                next_code,
            )
            .await?;
            let redirect_path = format!("/r/{code}");
            let response = CreateShortLinkResponse {
                code,
                url: command.url,
                redirect_path,
            };
            let body = serde_json::to_vec(&response).map_err(|_| ApiError::internal(request_id))?;
            let safe_response = SafeResponse::new(
                StatusCode::CREATED.as_u16(),
                Some(JSON_CONTENT_TYPE.to_owned()),
                body.clone(),
            )
            .map_err(|_| ApiError::internal(request_id))?;
            idempotency_store
                .complete_with(connection, identity, &safe_response)
                .await
                .map_err(|error| map_idempotency_error(error, request_id))?;
            Ok(CreateTransactionOutcome::Started(body))
        }
    }
}

async fn insert_with_bounded_collision_retry<F>(
    connection: &mut PgConnection,
    target_url: &str,
    request_id: RequestId,
    next_code: &mut F,
) -> Result<String, ApiError>
where
    F: FnMut() -> String,
{
    for _ in 0..MAX_CODE_ATTEMPTS {
        let code = next_code();
        if !valid_short_code(&code) {
            return Err(ApiError::internal(request_id));
        }
        let inserted = sqlx::query_scalar::<_, String>(
            r"
            INSERT INTO short_links (code, target_url)
            VALUES ($1, $2)
            ON CONFLICT (code) DO NOTHING
            RETURNING code
            ",
        )
        .bind(&code)
        .bind(target_url)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
        if inserted.is_some() {
            return Ok(code);
        }
    }
    Err(ApiError::database_unavailable(request_id))
}

async fn list_short_links(
    State(state): State<ApplicationState>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let rows = sqlx::query_as::<_, (String, String, bool)>(
        r"
        SELECT code, target_url, expired_at IS NOT NULL AS expired
        FROM short_links
        ORDER BY created_at DESC, code DESC
        LIMIT 100
        ",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| ApiError::database_unavailable(request_id))?;
    let links = rows
        .into_iter()
        .map(|(code, url, expired)| ShortLinkSummary { code, url, expired })
        .collect();
    json_response(
        StatusCode::OK,
        &ListShortLinksResponse { links },
        request_id,
    )
}

async fn resolve_short_link(
    State(state): State<ApplicationState>,
    request_id: Option<Extension<RequestId>>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let code = parse_short_code(path, request_id)?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let target_url = sqlx::query_scalar::<_, String>(
        r"
        SELECT target_url
        FROM short_links
        WHERE code = $1 AND expired_at IS NULL
        ",
    )
    .bind(code)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| ApiError::database_unavailable(request_id))?
    .ok_or_else(|| ApiError::not_found(request_id))?;
    let location =
        HeaderValue::from_str(&target_url).map_err(|_| ApiError::internal(request_id))?;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    response.headers_mut().insert(LOCATION, location);
    Ok(response)
}

async fn expire_short_link(
    State(state): State<ApplicationState>,
    request_id: Option<Extension<RequestId>>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let code = parse_short_code(path, request_id)?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let found = sqlx::query_scalar::<_, bool>(
        r"
        UPDATE short_links
        SET expired_at = clock_timestamp()
        WHERE code = $1
        RETURNING TRUE
        ",
    )
    .bind(code)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| ApiError::database_unavailable(request_id))?
    .unwrap_or(false);
    if !found {
        return Err(ApiError::not_found(request_id));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn create_identity(
    key: IdempotencyKey,
    command: &CreateShortLinkRequest,
    request_id: RequestId,
) -> Result<IdempotencyRequest, ApiError> {
    let body = serde_json::to_vec(command).map_err(|_| ApiError::internal(request_id))?;
    let mut canonical = Vec::with_capacity(CREATE_FINGERPRINT_PREFIX.len() + body.len());
    canonical.extend_from_slice(CREATE_FINGERPRINT_PREFIX);
    canonical.extend_from_slice(&body);
    let operation =
        IdempotencyOperation::new(CREATE_OPERATION).map_err(|_| ApiError::internal(request_id))?;
    Ok(IdempotencyRequest::new(
        IdempotencyScope::unscoped(),
        operation,
        key,
        RequestFingerprint::sha256(&canonical),
    ))
}

fn next_short_code() -> String {
    let random_tail = RequestId::new().as_uuid().as_u128() & 0x0000_ffff_ffff_ffff;
    format!("{random_tail:012x}")
}

fn validate_target_url(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > MAX_TARGET_URL_BYTES {
        return Err(());
    }
    let uri = value.parse::<axum::http::Uri>().map_err(|_| ())?;
    let scheme = uri.scheme_str().ok_or(())?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(());
    }
    let authority = uri.authority().ok_or(())?;
    if authority.host().is_empty() || authority.as_str().contains('@') {
        return Err(());
    }
    Ok(())
}

fn valid_short_code(value: &str) -> bool {
    value.len() == SHORT_CODE_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_short_code(
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    request_id: RequestId,
) -> Result<String, ApiError> {
    let Path(code) = path.map_err(|_| ApiError::invalid_code(request_id))?;
    if valid_short_code(&code) {
        Ok(code)
    } else {
        Err(ApiError::invalid_code(request_id))
    }
}

fn required_single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map_err(|_| ())
}

enum CreateTransactionOutcome {
    Started(Vec<u8>),
    Replay(SafeResponse),
    InProgress,
}

fn resolve_request_id(extension: Option<Extension<RequestId>>) -> RequestId {
    extension.map_or_else(RequestId::new, |Extension(request_id)| request_id)
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
    request_id: RequestId,
) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(body).map_err(|_| ApiError::internal(request_id))?;
    Ok(json_bytes_response(status, body))
}

fn json_bytes_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
    response
}

fn replay_response(response: &SafeResponse, request_id: RequestId) -> Result<Response, ApiError> {
    let status =
        StatusCode::from_u16(response.status()).map_err(|_| ApiError::internal(request_id))?;
    let mut replay = Response::new(Body::from(response.body().to_vec()));
    *replay.status_mut() = status;
    if let Some(content_type) = response.content_type() {
        let content_type =
            HeaderValue::from_str(content_type).map_err(|_| ApiError::internal(request_id))?;
        replay.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    Ok(replay)
}

fn map_json_rejection(error: &JsonRejection, request_id: RequestId) -> ApiError {
    match error.status() {
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "request body exceeds the configured limit",
            request_id,
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
            request_id,
        ),
        _ => ApiError::bad_request(
            "INVALID_JSON",
            "request body must be valid JSON",
            request_id,
        ),
    }
}

fn map_idempotency_error(error: IdempotencyStoreError, request_id: RequestId) -> ApiError {
    match error {
        IdempotencyStoreError::Conflict => ApiError::conflict(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency-Key was already used for a different request",
            request_id,
        ),
        IdempotencyStoreError::ClaimLost | IdempotencyStoreError::ClaimExpired => {
            ApiError::conflict(
                "IDEMPOTENCY_CLAIM_LOST",
                "idempotency claim can no longer be completed",
                request_id,
            )
        }
        IdempotencyStoreError::Transient(_)
        | IdempotencyStoreError::Unavailable
        | IdempotencyStoreError::ResponseTooLarge
        | IdempotencyStoreError::ConstraintViolation
        | IdempotencyStoreError::CorruptData => ApiError::database_unavailable(request_id),
    }
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

    const fn bad_request(code: &'static str, detail: &'static str, request_id: RequestId) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, detail, request_id)
    }

    const fn unprocessable(
        code: &'static str,
        detail: &'static str,
        request_id: RequestId,
    ) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, detail, request_id)
    }

    const fn conflict(code: &'static str, detail: &'static str, request_id: RequestId) -> Self {
        Self::new(StatusCode::CONFLICT, code, detail, request_id)
    }

    const fn invalid_code(request_id: RequestId) -> Self {
        Self::bad_request(
            "INVALID_SHORT_CODE",
            "short-link code must contain exactly 12 lowercase hexadecimal characters",
            request_id,
        )
    }

    const fn not_found(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "SHORT_LINK_NOT_FOUND",
            "short link was not found",
            request_id,
        )
    }

    const fn database_unavailable(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_UNAVAILABLE",
            "service is temporarily unavailable",
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
        let Ok(code) = ErrorCode::try_new(self.code) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let service_error = ServiceError::new(code, self.detail);
        let Ok(problem) =
            ProblemDetails::from_service_error(self.status, &service_error, self.request_id)
        else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        problem.into_response()
    }
}

fn problem_response(description: &'static str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/problem+json": {
                "schema": {"$ref": "#/components/schemas/ProblemDetails"}
            }
        }
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the complete application-owned OpenAPI document is intentionally kept in one value"
)]
fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Short Link Service",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "An anonymous PostgreSQL-backed short-link API."
        },
        "tags": [
            {
                "name": "short-links",
                "description": "Create, list, expire, and resolve short links."
            }
        ],
        "paths": {
            "/links": {
                "post": {
                    "operationId": "createShortLink",
                    "tags": ["short-links"],
                    "summary": "Create a short link",
                    "security": [],
                    "parameters": [
                        {
                            "name": "Idempotency-Key",
                            "in": "header",
                            "required": true,
                            "description": "One opaque visible-ASCII key. Reuse with the same request replays the original response.",
                            "schema": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 128,
                                "pattern": "^[!-~]+$"
                            }
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateShortLinkRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created short link or exact replay of the original response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CreateShortLinkResponse"}
                                }
                            }
                        },
                        "400": problem_response("Malformed JSON or invalid Idempotency-Key"),
                        "409": problem_response("Idempotency key conflicts with another request or an in-progress claim"),
                        "413": problem_response("Request body is too large"),
                        "415": problem_response("Content-Type is not application/json"),
                        "422": problem_response("Target URL is invalid"),
                        "503": problem_response("Persistence is unavailable")
                    }
                },
                "get": {
                    "operationId": "listShortLinks",
                    "tags": ["short-links"],
                    "summary": "List the 100 newest short links",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Newest-first short-link list",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ListShortLinksResponse"}
                                }
                            }
                        },
                        "503": problem_response("Persistence is unavailable")
                    }
                }
            },
            "/links/{code}": {
                "delete": {
                    "operationId": "expireShortLink",
                    "tags": ["short-links"],
                    "summary": "Logically expire a short link",
                    "security": [],
                    "parameters": [
                        {"$ref": "#/components/parameters/ShortCode"}
                    ],
                    "responses": {
                        "204": {"description": "Short link is expired"},
                        "400": problem_response("Short-link code is malformed"),
                        "404": problem_response("Short link does not exist"),
                        "503": problem_response("Persistence is unavailable")
                    }
                }
            },
            "/r/{code}": {
                "get": {
                    "operationId": "resolveShortLink",
                    "tags": ["short-links"],
                    "summary": "Resolve a live short link",
                    "security": [],
                    "parameters": [
                        {"$ref": "#/components/parameters/ShortCode"}
                    ],
                    "responses": {
                        "307": {
                            "description": "Redirect to the exact stored target",
                            "headers": {
                                "Location": {
                                    "required": true,
                                    "schema": {"type": "string", "format": "uri"}
                                }
                            }
                        },
                        "400": problem_response("Short-link code is malformed"),
                        "404": problem_response("Short link is missing or expired"),
                        "503": problem_response("Persistence is unavailable")
                    }
                }
            }
        },
        "components": {
            "parameters": {
                "ShortCode": {
                    "name": "code",
                    "in": "path",
                    "required": true,
                    "description": "Twelve-character lowercase hexadecimal short-link code",
                    "schema": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{12}$",
                        "minLength": 12,
                        "maxLength": 12
                    }
                }
            },
            "schemas": {
                "CreateShortLinkRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["url"],
                    "properties": {
                        "url": {
                            "type": "string",
                            "format": "uri",
                            "maxLength": 2048,
                            "description": "Absolute HTTP or HTTPS URI without embedded credentials"
                        }
                    }
                },
                "CreateShortLinkResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["code", "url", "redirect_path"],
                    "properties": {
                        "code": {"type": "string", "pattern": "^[0-9a-f]{12}$"},
                        "url": {"type": "string", "format": "uri"},
                        "redirect_path": {"type": "string", "pattern": "^/r/[0-9a-f]{12}$"}
                    }
                },
                "ShortLinkSummary": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["code", "url", "expired"],
                    "properties": {
                        "code": {"type": "string", "pattern": "^[0-9a-f]{12}$"},
                        "url": {"type": "string", "format": "uri"},
                        "expired": {"type": "boolean"}
                    }
                },
                "ListShortLinksResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["links"],
                    "properties": {
                        "links": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {"$ref": "#/components/schemas/ShortLinkSummary"}
                        }
                    }
                },
                "ProblemDetails": {
                    "type": "object",
                    "required": ["type", "title", "status", "code", "request_id"],
                    "properties": {
                        "type": {"type": "string", "format": "uri"},
                        "title": {"type": "string"},
                        "status": {"type": "integer", "minimum": 400, "maximum": 599},
                        "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
                        "request_id": {"type": "string", "format": "uuid"},
                        "detail": {"type": "string"},
                        "errors": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {
                                "type": "object",
                                "required": ["pointer", "code", "message"],
                                "properties": {
                                    "pointer": {"type": "string"},
                                    "code": {"type": "string"},
                                    "message": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test setup uses expect only for static fixtures and impossible branches"
)]
mod tests {
    use std::{
        collections::VecDeque,
        error::Error,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::http::{Method, Request};
    use http_body_util::BodyExt as _;
    use service_kit::config::{DeploymentEnvironment, SecretString};
    use service_kit::{
        idempotency::{IdempotencyConfig, IdempotencyKey},
        postgres::{PostgresConfig, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig},
        test_support::PostgresFixture,
    };
    use tower::ServiceExt as _;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn target_url_validation_enforces_absolute_credential_free_http_urls() {
        for valid in [
            "https://example.com/docs?a=1",
            "http://example.com",
            "http://127.0.0.1:8080/path",
            "https://[2001:db8::1]/%7Euser",
        ] {
            assert!(validate_target_url(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "/relative",
            "ftp://example.com/file",
            "https:///missing-authority",
            "https://user:password@example.com/private",
            "https://example.com/\nheader",
        ] {
            assert!(validate_target_url(invalid).is_err(), "{invalid}");
        }
        assert!(
            validate_target_url(&format!(
                "https://example.com/{}",
                "a".repeat(MAX_TARGET_URL_BYTES)
            ))
            .is_err()
        );
    }

    #[test]
    fn short_code_validation_requires_exact_lowercase_hex() {
        assert!(valid_short_code("012345abcdef"));
        for invalid in [
            "012345abcde",
            "012345abcdef0",
            "012345ABCDEf",
            "012345abcdeg",
            "012345abcde-",
        ] {
            assert!(!valid_short_code(invalid), "{invalid}");
        }
    }

    #[test]
    fn openapi_document_exactly_covers_declared_anonymous_operations() {
        let document = openapi_document();
        let operation_count = document["paths"]
            .as_object()
            .expect("paths")
            .values()
            .map(|path| {
                [
                    "get", "put", "post", "delete", "options", "head", "patch", "trace",
                ]
                .into_iter()
                .filter(|method| path.get(*method).is_some())
                .count()
            })
            .sum::<usize>();
        assert_eq!(operation_count, APPLICATION_OPERATIONS.len());
        for operation in APPLICATION_OPERATIONS {
            let contract = &document["paths"][operation.path][operation.method];
            assert_eq!(
                contract["operationId"].as_str(),
                Some(operation.operation_id)
            );
            assert_eq!(contract["tags"][0].as_str(), Some(operation.tag));
            assert_eq!(contract["security"].as_array().map(Vec::len), Some(0));
        }
        assert_eq!(
            document["components"]["schemas"]["ProblemDetails"]["required"],
            json!(["type", "title", "status", "code", "request_id"])
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one container exercises the complete stateful HTTP lifecycle without repeated startup"
    )]
    async fn postgres_handlers_cover_lifecycle_idempotency_collisions_and_failures() -> TestResult {
        let fixture = PostgresFixture::start().await?;
        let pool = PostgresPool::connect(
            &postgres_config(fixture.database_url().clone()),
            DeploymentEnvironment::Test,
        )
        .await?;
        let sqlx_pool = pool.sqlx_pool();
        crate::prepared_migrations()
            .await?
            .as_migrator()
            .run(&sqlx_pool)
            .await?;
        let state = ApplicationState {
            pool: pool.clone(),
            idempotency_store: PostgresIdempotencyStore::new(IdempotencyConfig::default())?,
        };
        let router = application_router(state.clone());

        let original_body = r#"{"url":"https://example.com/docs?a=1"}"#;
        let created = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                Some("create-one"),
                original_body,
            ))
            .await?;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_content_type = created.headers()[CONTENT_TYPE].clone();
        let created_bytes = created.into_body().collect().await?.to_bytes();
        let created_document: CreateShortLinkResponse = serde_json::from_slice(&created_bytes)?;
        assert!(valid_short_code(&created_document.code));
        assert_eq!(created_document.url, "https://example.com/docs?a=1");
        assert_eq!(
            created_document.redirect_path,
            format!("/r/{}", created_document.code)
        );

        let replayed = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                Some("create-one"),
                original_body,
            ))
            .await?;
        assert_eq!(replayed.status(), StatusCode::CREATED);
        assert_eq!(replayed.headers()[CONTENT_TYPE], created_content_type);
        assert_eq!(
            replayed.into_body().collect().await?.to_bytes(),
            created_bytes
        );

        let mismatch = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                Some("create-one"),
                r#"{"url":"https://example.org/changed"}"#,
            ))
            .await?;
        assert_problem(&mismatch, StatusCode::CONFLICT);
        let in_progress_body = r#"{"url":"https://example.org/in-progress"}"#;
        let in_progress_command = CreateShortLinkRequest {
            url: "https://example.org/in-progress".to_owned(),
        };
        let in_progress_identity = create_identity(
            IdempotencyKey::try_from("create-in-progress")?,
            &in_progress_command,
            RequestId::new(),
        )
        .expect("valid static operation");
        let mut claim_connection = pool.acquire().await?;
        let mut claim_transaction = claim_connection.begin().await?;
        assert_eq!(
            state
                .idempotency_store
                .claim_with(&mut claim_transaction, &in_progress_identity)
                .await?,
            ClaimOutcome::Started
        );
        claim_transaction.commit().await?;
        drop(claim_connection);
        let in_progress = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                Some("create-in-progress"),
                in_progress_body,
            ))
            .await?;
        assert_problem(&in_progress, StatusCode::CONFLICT);

        let missing_key = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                None,
                r#"{"url":"https://example.com"}"#,
            ))
            .await?;
        assert_problem(&missing_key, StatusCode::BAD_REQUEST);

        let unknown_field = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                Some("strict-json"),
                r#"{"url":"https://example.com","alias":"forbidden"}"#,
            ))
            .await?;
        assert_problem(&unknown_field, StatusCode::BAD_REQUEST);

        let invalid_url = router
            .clone()
            .oneshot(json_request(
                Method::POST,
                LINKS_PATH,
                Some("invalid-url"),
                r#"{"url":"/relative"}"#,
            ))
            .await?;
        assert_problem(&invalid_url, StatusCode::UNPROCESSABLE_ENTITY);
        let malformed_code = router
            .clone()
            .oneshot(empty_request(Method::GET, "/r/not-hex"))
            .await?;
        assert_problem(&malformed_code, StatusCode::BAD_REQUEST);

        let listed = router
            .clone()
            .oneshot(empty_request(Method::GET, LINKS_PATH))
            .await?;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed: ListShortLinksResponse =
            serde_json::from_slice(&listed.into_body().collect().await?.to_bytes())?;
        assert!(listed.links.len() <= 100);
        assert!(listed.links.iter().any(|link| {
            link.code == created_document.code && link.url == created_document.url && !link.expired
        }));

        let redirect_path = format!("/r/{}", created_document.code);
        let redirected = router
            .clone()
            .oneshot(empty_request(Method::GET, &redirect_path))
            .await?;
        assert_eq!(redirected.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            redirected.headers()[LOCATION],
            HeaderValue::from_static("https://example.com/docs?a=1")
        );

        let link_path = format!("/links/{}", created_document.code);
        for _ in 0..2 {
            let expired = router
                .clone()
                .oneshot(empty_request(Method::DELETE, &link_path))
                .await?;
            assert_eq!(expired.status(), StatusCode::NO_CONTENT);
        }
        let expired_redirect = router
            .clone()
            .oneshot(empty_request(Method::GET, &redirect_path))
            .await?;
        assert_problem(&expired_redirect, StatusCode::NOT_FOUND);

        sqlx::query(
            "INSERT INTO short_links (code, target_url) VALUES ('aaaaaaaaaaaa', 'https://collision.example')",
        )
        .execute(&sqlx_pool)
        .await?;
        let collision_command = CreateShortLinkRequest {
            url: "https://example.net/collision-retry".to_owned(),
        };
        let collision_identity = create_identity(
            IdempotencyKey::try_from("collision-retry")?,
            &collision_command,
            RequestId::new(),
        )
        .expect("valid static operation");
        let mut codes = VecDeque::from(["aaaaaaaaaaaa".to_owned(), "bbbbbbbbbbbb".to_owned()]);
        let collision_response = create_short_link_with(
            &state,
            &collision_identity,
            collision_command,
            RequestId::new(),
            move || codes.pop_front().expect("bounded sequence"),
        )
        .await
        .expect("second code should be allocated");
        let collision_body: CreateShortLinkResponse =
            serde_json::from_slice(&collision_response.into_body().collect().await?.to_bytes())?;
        assert_eq!(collision_body.code, "bbbbbbbbbbbb");

        for code in [
            "cccccccccccc",
            "dddddddddddd",
            "eeeeeeeeeeee",
            "ffffffffffff",
            "000000000000",
        ] {
            sqlx::query("INSERT INTO short_links (code, target_url) VALUES ($1, $2)")
                .bind(code)
                .bind("https://collision.example")
                .execute(&sqlx_pool)
                .await?;
        }
        let exhausted_command = CreateShortLinkRequest {
            url: "https://example.net/collision-exhausted".to_owned(),
        };
        let exhausted_identity = create_identity(
            IdempotencyKey::try_from("collision-exhausted")?,
            &exhausted_command,
            RequestId::new(),
        )
        .expect("valid static operation");
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempt_counter = Arc::clone(&attempts);
        let mut colliding_codes = VecDeque::from([
            "cccccccccccc".to_owned(),
            "dddddddddddd".to_owned(),
            "eeeeeeeeeeee".to_owned(),
            "ffffffffffff".to_owned(),
            "000000000000".to_owned(),
        ]);
        let exhausted = create_short_link_with(
            &state,
            &exhausted_identity,
            exhausted_command,
            RequestId::new(),
            move || {
                attempt_counter.fetch_add(1, Ordering::Relaxed);
                colliding_codes.pop_front().expect("five attempts")
            },
        )
        .await;
        let Err(error) = exhausted else {
            panic!("five primary-key collisions unexpectedly allocated a code");
        };
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(attempts.load(Ordering::Relaxed), MAX_CODE_ATTEMPTS);

        for scaffold in ["/example", "/reference-records"] {
            let response = router
                .clone()
                .oneshot(empty_request(Method::GET, scaffold))
                .await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        pool.close().await?;
        let unavailable = router
            .oneshot(empty_request(Method::GET, LINKS_PATH))
            .await?;
        assert_problem(&unavailable, StatusCode::SERVICE_UNAVAILABLE);
        let unavailable_body: Value =
            serde_json::from_slice(&unavailable.into_body().collect().await?.to_bytes())?;
        assert_eq!(unavailable_body["code"], "DATABASE_UNAVAILABLE");

        fixture.cleanup().await?;
        Ok(())
    }

    fn postgres_config(url: SecretString) -> PostgresConfig {
        PostgresConfig {
            url,
            tls_mode: PostgresTlsMode::Disable,
            min_connections: 1,
            max_connections: 2,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(60),
            max_lifetime_jitter: Duration::from_secs(10),
            application_name: "short-link-service-test".to_owned(),
            initialization_sql: Vec::new(),
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(1),
            health_timeout: Duration::from_secs(2),
            shutdown_timeout: Duration::from_secs(3),
            transaction_retry: TransactionRetryConfig {
                max_attempts: 3,
                base_delay: Duration::from_millis(5),
                max_delay: Duration::from_millis(50),
                max_jitter: Duration::from_millis(5),
                isolation: TransactionIsolation::Serializable,
            },
        }
    }

    fn json_request(
        method: Method,
        uri: &str,
        idempotency_key: Option<&str>,
        body: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, JSON_CONTENT_TYPE);
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        builder
            .body(Body::from(body.to_owned()))
            .expect("valid request")
    }

    fn empty_request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("valid request")
    }

    fn assert_problem(response: &Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            HeaderValue::from_static("application/problem+json")
        );
    }
}
