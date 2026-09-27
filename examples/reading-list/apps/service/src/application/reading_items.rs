use axum::{
    Json, Router,
    body::Body,
    extract::{
        Extension, Path, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH},
    },
    response::Response,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use service_kit::{
    ErrorCode, ExpectedOperation, RequestId, ServiceError,
    auth::Principal,
    http::{FieldError, IfMatch, ProblemDetails, VersionEtag},
    postgres::{
        PostgresPool,
        sqlx::{self, Connection as _},
    },
};
use time::OffsetDateTime;
use url::Url;
use uuid::{Uuid, Variant, Version};

const COLLECTION_PATH: &str = "/api/reading-items";
const ITEM_PATH: &str = "/api/reading-items/{item_id}";
const MAX_ITEMS_PER_OWNER: i64 = 500;
const JSON_CONTENT_TYPE: &str = "application/json";
const OWNER_URL_CONSTRAINT: &str = "reading_items_owner_url_unique";

pub(crate) const ROUTES: &[&str] = &[COLLECTION_PATH, ITEM_PATH];
pub(crate) const OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new("get", COLLECTION_PATH, "listReadingItems", "reading-items"),
    ExpectedOperation::new(
        "post",
        COLLECTION_PATH,
        "createReadingItem",
        "reading-items",
    ),
    ExpectedOperation::new("patch", ITEM_PATH, "updateReadingItem", "reading-items"),
    ExpectedOperation::new("delete", ITEM_PATH, "deleteReadingItem", "reading-items"),
];

#[derive(Clone)]
struct ReadingItemsState {
    pool: PostgresPool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateReadingItemRequest {
    title: String,
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateReadingItemRequest {
    finished: bool,
}

#[derive(Deserialize)]
struct ReadingItemPath {
    item_id: String,
}

#[derive(Serialize)]
struct ReadingItem {
    id: Uuid,
    title: String,
    url: String,
    finished: bool,
    version: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

type ReadingItemRow = (
    Uuid,
    String,
    String,
    bool,
    i64,
    OffsetDateTime,
    OffsetDateTime,
);

impl TryFrom<ReadingItemRow> for ReadingItem {
    type Error = ();

    fn try_from(row: ReadingItemRow) -> Result<Self, Self::Error> {
        if row.4 <= 0 {
            return Err(());
        }
        Ok(Self {
            id: row.0,
            title: row.1,
            url: row.2,
            finished: row.3,
            version: row.4,
            created_at: row.5,
            updated_at: row.6,
        })
    }
}

pub(crate) fn router(pool: PostgresPool) -> Router {
    Router::new()
        .route(
            COLLECTION_PATH,
            get(list_reading_items).post(create_reading_item),
        )
        .route(
            ITEM_PATH,
            axum::routing::patch(update_reading_item).delete(delete_reading_item),
        )
        .with_state(ReadingItemsState { pool })
}

async fn list_reading_items(
    State(state): State<ReadingItemsState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let owner_id = principal.subject_id.as_uuid();
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let rows = sqlx::query_as::<_, ReadingItemRow>(
        "SELECT id, title, url, finished, version, created_at, updated_at \
         FROM reading_items \
         WHERE owner_id = $1 \
         ORDER BY finished ASC, created_at DESC, id DESC \
         LIMIT 500",
    )
    .bind(owner_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error, request_id))?;
    let items = rows
        .into_iter()
        .map(ReadingItem::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| ApiError::internal(request_id))?;
    json_response(StatusCode::OK, &items, request_id, true)
}

async fn create_reading_item(
    State(state): State<ReadingItemsState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<CreateReadingItemRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let Json(command) = payload.map_err(|error| map_json_rejection(&error, request_id))?;
    let title = validate_title(command.title, request_id)?;
    let url = canonicalize_url(&command.url, request_id)?;
    let owner_id = principal.subject_id.as_uuid();
    let id = Uuid::now_v7();

    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(owner_advisory_lock(owner_id))
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reading_items WHERE owner_id = $1")
            .bind(owner_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| map_sqlx_error(&error, request_id))?;
    if count >= MAX_ITEMS_PER_OWNER {
        return Err(ApiError::capacity_exceeded(request_id));
    }
    let row = sqlx::query_as::<_, ReadingItemRow>(
        "INSERT INTO reading_items (id, owner_id, title, url) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, title, url, finished, version, created_at, updated_at",
    )
    .bind(id)
    .bind(owner_id)
    .bind(title)
    .bind(url)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| map_insert_error(&error, request_id))?;
    let item = ReadingItem::try_from(row).map_err(|()| ApiError::internal(request_id))?;
    let response = item_response(StatusCode::CREATED, &item, request_id)?;
    transaction
        .commit()
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    Ok(response)
}

async fn update_reading_item(
    State(state): State<ReadingItemsState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    path: Result<Path<ReadingItemPath>, PathRejection>,
    payload: Result<Json<UpdateReadingItemRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let item_id = parse_item_id(path, request_id)?;
    let expected_version = parse_required_if_match(&headers, request_id)?;
    let Json(command) = payload.map_err(|error| map_json_rejection(&error, request_id))?;
    let owner_id = principal.subject_id.as_uuid();

    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    let current_version = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM reading_items \
         WHERE id = $1 AND owner_id = $2 \
         FOR UPDATE",
    )
    .bind(item_id)
    .bind(owner_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| map_sqlx_error(&error, request_id))?
    .ok_or_else(|| ApiError::not_found(request_id))?;
    if current_version <= 0
        || u64::try_from(current_version).ok() != Some(expected_version.version())
    {
        return Err(ApiError::precondition_failed(request_id));
    }
    let row = sqlx::query_as::<_, ReadingItemRow>(
        "UPDATE reading_items \
         SET finished = $3, version = version + 1, updated_at = clock_timestamp() \
         WHERE id = $1 AND owner_id = $2 \
         RETURNING id, title, url, finished, version, created_at, updated_at",
    )
    .bind(item_id)
    .bind(owner_id)
    .bind(command.finished)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| map_sqlx_error(&error, request_id))?
    .ok_or_else(|| ApiError::not_found(request_id))?;
    let item = ReadingItem::try_from(row).map_err(|()| ApiError::internal(request_id))?;
    let response = item_response(StatusCode::OK, &item, request_id)?;
    transaction
        .commit()
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    Ok(response)
}

async fn delete_reading_item(
    State(state): State<ReadingItemsState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    path: Result<Path<ReadingItemPath>, PathRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let item_id = parse_item_id(path, request_id)?;
    let expected_version = parse_required_if_match(&headers, request_id)?;
    let owner_id = principal.subject_id.as_uuid();

    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    let current_version = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM reading_items \
         WHERE id = $1 AND owner_id = $2 \
         FOR UPDATE",
    )
    .bind(item_id)
    .bind(owner_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| map_sqlx_error(&error, request_id))?
    .ok_or_else(|| ApiError::not_found(request_id))?;
    if current_version <= 0
        || u64::try_from(current_version).ok() != Some(expected_version.version())
    {
        return Err(ApiError::precondition_failed(request_id));
    }
    let deleted =
        sqlx::query("DELETE FROM reading_items WHERE id = $1 AND owner_id = $2 AND version = $3")
            .bind(item_id)
            .bind(owner_id)
            .bind(current_version)
            .execute(&mut *transaction)
            .await
            .map_err(|error| map_sqlx_error(&error, request_id))?;
    if deleted.rows_affected() != 1 {
        return Err(ApiError::precondition_failed(request_id));
    }
    transaction
        .commit()
        .await
        .map_err(|error| map_sqlx_error(&error, request_id))?;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    set_no_store(&mut response);
    Ok(response)
}

fn validate_title(title: String, request_id: RequestId) -> Result<String, ApiError> {
    let trimmed = title.trim();
    if trimmed.is_empty() || trimmed.len() > 200 {
        return Err(ApiError::validation(
            request_id,
            TITLE_FIELD_ERRORS,
            "reading item title is invalid",
        ));
    }
    if trimmed.len() == title.len() {
        Ok(title)
    } else {
        Ok(trimmed.to_owned())
    }
}

fn canonicalize_url(value: &str, request_id: RequestId) -> Result<String, ApiError> {
    let parsed = Url::parse(value).map_err(|_| {
        ApiError::validation(request_id, URL_FIELD_ERRORS, "reading item URL is invalid")
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || authority_contains_userinfo(value)
    {
        return Err(ApiError::validation(
            request_id,
            URL_FIELD_ERRORS,
            "reading item URL is invalid",
        ));
    }
    let canonical = parsed.to_string();
    if canonical.len() > 2_048 {
        return Err(ApiError::validation(
            request_id,
            URL_FIELD_ERRORS,
            "reading item URL is invalid",
        ));
    }
    Ok(canonical)
}

fn authority_contains_userinfo(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

fn parse_item_id(
    path: Result<Path<ReadingItemPath>, PathRejection>,
    request_id: RequestId,
) -> Result<Uuid, ApiError> {
    let Path(path) = path.map_err(|_| ApiError::invalid_item_id(request_id))?;
    let id = Uuid::parse_str(&path.item_id).map_err(|_| ApiError::invalid_item_id(request_id))?;
    if id.get_version() != Some(Version::SortRand) || id.get_variant() != Variant::RFC4122 {
        return Err(ApiError::invalid_item_id(request_id));
    }
    Ok(id)
}

fn parse_required_if_match(
    headers: &HeaderMap,
    request_id: RequestId,
) -> Result<VersionEtag, ApiError> {
    let mut values = headers.get_all(IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(ApiError::precondition_required(request_id));
    };
    if values.next().is_some() {
        return Err(ApiError::invalid_if_match(request_id));
    }
    match IfMatch::from_header_value(value) {
        Ok(IfMatch::Exact(tag)) => Ok(tag),
        Ok(IfMatch::Any) | Err(_) => Err(ApiError::invalid_if_match(request_id)),
    }
}

fn owner_advisory_lock(owner_id: Uuid) -> i64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&owner_id.as_bytes()[..8]);
    i64::from_be_bytes(bytes)
}

fn map_insert_error(error: &sqlx::Error, request_id: RequestId) -> ApiError {
    if error
        .as_database_error()
        .and_then(|database| database.constraint())
        == Some(OWNER_URL_CONSTRAINT)
    {
        ApiError::duplicate(request_id)
    } else {
        map_sqlx_error(error, request_id)
    }
}

fn map_sqlx_error(error: &sqlx::Error, request_id: RequestId) -> ApiError {
    let transient_database_failure = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code.starts_with("08"));
    if transient_database_failure
        || matches!(
            error,
            sqlx::Error::Io(_)
                | sqlx::Error::Tls(_)
                | sqlx::Error::Protocol(_)
                | sqlx::Error::PoolTimedOut
                | sqlx::Error::PoolClosed
                | sqlx::Error::WorkerCrashed
        )
    {
        ApiError::database_unavailable(request_id)
    } else {
        ApiError::internal(request_id)
    }
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
        _ => ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_JSON",
            "request body must be valid JSON and contain only supported fields",
            request_id,
        ),
    }
}

fn resolve_request_id(extension: Option<Extension<RequestId>>) -> RequestId {
    extension.map_or_else(RequestId::new, |Extension(request_id)| request_id)
}

fn item_response(
    status: StatusCode,
    item: &ReadingItem,
    request_id: RequestId,
) -> Result<Response, ApiError> {
    let version = u64::try_from(item.version).map_err(|_| ApiError::internal(request_id))?;
    let etag = VersionEtag::new(version)
        .and_then(VersionEtag::to_header_value)
        .map_err(|_| ApiError::internal(request_id))?;
    let mut response = json_response(status, item, request_id, true)?;
    response.headers_mut().insert(ETAG, etag);
    Ok(response)
}

fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
    request_id: RequestId,
    no_store: bool,
) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(value).map_err(|_| ApiError::internal(request_id))?;
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
    if no_store {
        set_no_store(&mut response);
    }
    Ok(response)
}

fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[derive(Clone, Copy)]
struct ApiFieldError {
    pointer: &'static str,
    code: &'static str,
    message: &'static str,
}

const TITLE_FIELD_ERRORS: &[ApiFieldError] = &[ApiFieldError {
    pointer: "/title",
    code: "invalid",
    message: "Enter a title containing 1 to 200 UTF-8 bytes.",
}];
const URL_FIELD_ERRORS: &[ApiFieldError] = &[ApiFieldError {
    pointer: "/url",
    code: "invalid",
    message: "Enter an absolute HTTP or HTTPS URL with a host and no credentials.",
}];

#[derive(Clone, Copy)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
    field_errors: &'static [ApiFieldError],
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
            field_errors: &[],
        }
    }

    const fn validation(
        request_id: RequestId,
        field_errors: &'static [ApiFieldError],
        detail: &'static str,
    ) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "VALIDATION_FAILED",
            detail,
            request_id,
            field_errors,
        }
    }

    const fn invalid_item_id(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "INVALID_READING_ITEM_ID",
            "reading item identifier is invalid",
            request_id,
        )
    }

    const fn invalid_if_match(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "INVALID_IF_MATCH",
            "If-Match must contain exactly one strong version tag",
            request_id,
        )
    }

    const fn precondition_required(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
            "If-Match is required",
            request_id,
        )
    }

    const fn precondition_failed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
            "If-Match does not match the current reading item version",
            request_id,
        )
    }

    const fn not_found(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "READING_ITEM_NOT_FOUND",
            "reading item was not found",
            request_id,
        )
    }

    const fn duplicate(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "READING_ITEM_EXISTS",
            "a reading item with this URL already exists",
            request_id,
        )
    }

    const fn capacity_exceeded(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "READING_LIST_CAPACITY_EXCEEDED",
            "the reading list already contains 500 items",
            request_id,
        )
    }

    const fn database_unavailable(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_UNAVAILABLE",
            "reading list persistence is unavailable",
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
                let error = ServiceError::new(code, self.detail);
                let problem =
                    ProblemDetails::from_service_error(self.status, &error, self.request_id)
                        .ok()?;
                if self.field_errors.is_empty() {
                    Some(problem)
                } else {
                    let errors = self
                        .field_errors
                        .iter()
                        .map(|error| {
                            FieldError::try_new(error.pointer, error.code, error.message).ok()
                        })
                        .collect::<Option<Vec<_>>>()?;
                    problem.with_errors(errors).ok()
                }
            })
            .map_or_else(
                || StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                axum::response::IntoResponse::into_response,
            );
        let mut response = response;
        set_no_store(&mut response);
        response
    }
}

pub(crate) fn openapi_fragment() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "reading-list", "version": env!("CARGO_PKG_VERSION")},
        "paths": {
            "/api/reading-items": collection_path_contract(),
            "/api/reading-items/{item_id}": item_path_contract()
        },
        "components": component_contracts()
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": {
            "Cache-Control": {
                "description": "Prevents storage of error details.",
                "schema": {"type": "string", "const": "no-store"}
            }
        },
        "content": {
            "application/problem+json": {
                "schema": {"$ref": "#/components/schemas/ProblemDetailsSchema"}
            }
        }
    })
}

fn collection_path_contract() -> Value {
    json!({
        "get": {
            "operationId": "listReadingItems",
            "tags": ["reading-items"],
            "security": [{"session_cookie": []}],
            "responses": {
                "200": {
                    "description": "Owner-scoped reading items, unfinished first and newest first",
                    "headers": {"Cache-Control": {"description": "Prevents storage of the owner-scoped response.", "schema": {"type": "string", "const": "no-store"}}},
                    "content": {"application/json": {"schema": {"type": "array", "maxItems": 500, "items": {"$ref": "#/components/schemas/ReadingItem"}}}}
                },
                "401": problem_response("Authentication missing, expired, or revoked."),
                "500": problem_response("Internal service failure."),
                "503": problem_response("Persistence unavailable.")
            }
        },
        "post": {
            "operationId": "createReadingItem",
            "tags": ["reading-items"],
            "security": [{"session_cookie": []}],
            "requestBody": {
                "required": true,
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateReadingItemRequest"}}}
            },
            "responses": {
                "201": {
                    "description": "Reading item created.",
                    "headers": {
                        "ETag": {"description": "Strong version entity tag.", "required": true, "schema": {"type": "string", "pattern": "^\\\"v[1-9][0-9]*\\\"$"}},
                        "Cache-Control": {"description": "Prevents storage of the mutation response.", "schema": {"type": "string", "const": "no-store"}}
                    },
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReadingItem"}}}
                },
                "400": problem_response("Malformed JSON."),
                "401": problem_response("Authentication missing, expired, or revoked."),
                "409": problem_response("The URL already exists or the reading list is at capacity."),
                "413": problem_response("Request body too large."),
                "415": problem_response("Unsupported request media type."),
                "422": problem_response("Request validation failed."),
                "500": problem_response("Internal service failure."),
                "503": problem_response("Persistence unavailable.")
            }
        }
    })
}

fn item_path_contract() -> Value {
    json!({
        "parameters": [{
            "name": "item_id", "in": "path", "required": true,
            "description": "Reading item UUIDv7.",
            "schema": {"type": "string", "format": "uuid", "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"}
        }],
        "patch": {
            "operationId": "updateReadingItem",
            "tags": ["reading-items"],
            "security": [{"session_cookie": []}],
            "parameters": [{"$ref": "#/components/parameters/IfMatch"}],
            "requestBody": {
                "required": true,
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UpdateReadingItemRequest"}}}
            },
            "responses": {
                "200": {
                    "description": "Reading item updated.",
                    "headers": {
                        "ETag": {"description": "Strong version entity tag.", "required": true, "schema": {"type": "string", "pattern": "^\\\"v[1-9][0-9]*\\\"$"}},
                        "Cache-Control": {"description": "Prevents storage of the mutation response.", "schema": {"type": "string", "const": "no-store"}}
                    },
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReadingItem"}}}
                },
                "400": problem_response("Malformed item identifier, If-Match, or JSON."),
                "401": problem_response("Authentication missing, expired, or revoked."),
                "404": problem_response("Reading item not found."),
                "412": problem_response("Version precondition failed."),
                "413": problem_response("Request body too large."),
                "415": problem_response("Unsupported request media type."),
                "428": problem_response("If-Match precondition required."),
                "500": problem_response("Internal service failure."),
                "503": problem_response("Persistence unavailable.")
            }
        },
        "delete": {
            "operationId": "deleteReadingItem",
            "tags": ["reading-items"],
            "security": [{"session_cookie": []}],
            "parameters": [{"$ref": "#/components/parameters/IfMatch"}],
            "responses": {
                "204": {
                    "description": "Reading item deleted.",
                    "headers": {"Cache-Control": {"description": "Prevents storage of the mutation response.", "schema": {"type": "string", "const": "no-store"}}}
                },
                "400": problem_response("Malformed item identifier or If-Match."),
                "401": problem_response("Authentication missing, expired, or revoked."),
                "404": problem_response("Reading item not found."),
                "412": problem_response("Version precondition failed."),
                "428": problem_response("If-Match precondition required."),
                "500": problem_response("Internal service failure."),
                "503": problem_response("Persistence unavailable.")
            }
        }
    })
}

fn component_contracts() -> Value {
    json!({
        "parameters": {
            "IfMatch": {
                "name": "If-Match", "in": "header", "required": true,
                "description": "Exactly one current strong version entity tag; weak tags, lists, and wildcard are rejected.",
                "schema": {"type": "string", "pattern": "^\\\"v[1-9][0-9]*\\\"$"}
            }
        },
        "schemas": {
            "ReadingItem": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "title", "url", "finished", "version", "created_at", "updated_at"],
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "title": {"type": "string", "minLength": 1, "maxLength": 200},
                    "url": {"type": "string", "format": "uri", "maxLength": 2048},
                    "finished": {"type": "boolean"},
                    "version": {"type": "integer", "format": "int64", "minimum": 1},
                    "created_at": {"type": "string", "format": "date-time"},
                    "updated_at": {"type": "string", "format": "date-time"}
                }
            },
            "CreateReadingItemRequest": {
                "type": "object", "additionalProperties": false,
                "required": ["title", "url"],
                "properties": {
                    "title": {"type": "string", "description": "Trimmed title containing 1 to 200 UTF-8 bytes."},
                    "url": {"type": "string", "description": "Absolute canonical HTTP(S) URL with a host and no credentials.", "maxLength": 2048}
                }
            },
            "UpdateReadingItemRequest": {
                "type": "object", "additionalProperties": false,
                "required": ["finished"],
                "properties": {"finished": {"type": "boolean"}}
            }
        }
    })
}

#[cfg(test)]
#[expect(
    clippy::too_many_lines,
    reason = "one PostgreSQL fixture covers the stateful product contract without repeated containers"
)]
mod tests {
    use std::{error::Error, time::Duration};

    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use http_body_util::BodyExt as _;
    use service_kit::{
        auth::{AssuranceLevel, AuthMethod, PrincipalKind, SubjectId},
        config::{DeploymentEnvironment, SecretString},
        postgres::{PostgresConfig, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig},
        test_support::PostgresFixture,
    };
    use tower::{ServiceBuilder, ServiceExt as _};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[tokio::test]
    async fn migrations_and_product_http_contract_hold_under_real_postgres() -> TestResult {
        let fixture = PostgresFixture::start().await?;
        let pool = PostgresPool::connect(
            &postgres_config(fixture.database_url().clone()),
            DeploymentEnvironment::Test,
        )
        .await?;
        crate::prepared_migrations()
            .await?
            .as_migrator()
            .run(&pool.sqlx_pool())
            .await?;
        let table_exists =
            sqlx::query_scalar::<_, bool>("SELECT to_regclass('public.reading_items') IS NOT NULL")
                .fetch_one(&pool.sqlx_pool())
                .await?;
        assert!(table_exists);

        let first = test_principal()?;
        let second = test_principal()?;
        seed_user(&pool, &first).await?;
        seed_user(&pool, &second).await?;
        let first_router = principal_router(pool.clone(), first.clone());
        let second_router = principal_router(pool.clone(), second.clone());

        let empty = send(&first_router, Method::GET, COLLECTION_PATH, None, None).await?;
        assert_eq!(empty.status(), StatusCode::OK);
        assert_eq!(json_body(empty).await?, json!([]));

        let fifty_emoji = "😀".repeat(50);
        let accepted = create(&first_router, &fifty_emoji, "HTTPS://Example.COM/docs").await?;
        assert_eq!(accepted.status(), StatusCode::CREATED);
        assert_eq!(
            accepted.headers().get(ETAG),
            Some(&HeaderValue::from_static("\"v1\""))
        );
        let accepted_body = json_body(accepted).await?;
        assert_eq!(accepted_body["title"], fifty_emoji);
        assert_eq!(accepted_body["url"], "https://example.com/docs");
        let accepted_id = value_id(&accepted_body)?;

        let too_many_emoji = create(
            &first_router,
            &"😀".repeat(51),
            "https://example.com/too-many",
        )
        .await?;
        assert_problem(
            too_many_emoji,
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_FAILED",
        )
        .await?;
        for (body, status, code) in [
            (
                r#"{"title":" ","url":"https://example.com/blank"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED",
            ),
            (
                r#"{"title":"bad","url":"ftp://example.com/file"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED",
            ),
            (
                r#"{"title":"bad","url":"https://user@example.com/private"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED",
            ),
            (
                r#"{"title":"strict","url":"https://example.com/strict","extra":true}"#,
                StatusCode::BAD_REQUEST,
                "INVALID_JSON",
            ),
            (
                r#"{"title":"unterminated""#,
                StatusCode::BAD_REQUEST,
                "INVALID_JSON",
            ),
        ] {
            let response = send(
                &first_router,
                Method::POST,
                COLLECTION_PATH,
                Some(body),
                None,
            )
            .await?;
            assert_problem(response, status, code).await?;
        }

        let duplicate = create(
            &first_router,
            "Same canonical URL",
            "https://example.com/docs",
        )
        .await?;
        assert_problem(duplicate, StatusCode::CONFLICT, "READING_ITEM_EXISTS").await?;
        let other_owner_same_url = create(
            &second_router,
            "Independent owner",
            "https://example.com/docs",
        )
        .await?;
        assert_eq!(other_owner_same_url.status(), StatusCode::CREATED);

        let older = create(
            &first_router,
            "Older unfinished",
            "https://example.com/older",
        )
        .await?;
        let older_id = value_id(&json_body(older).await?)?;
        let newer = create(
            &first_router,
            "Newest unfinished",
            "https://example.com/newer",
        )
        .await?;
        let newer_body = json_body(newer).await?;
        let newer_id = value_id(&newer_body)?;
        sqlx::query(
            "UPDATE reading_items SET created_at = CASE WHEN id = $1 THEN \
             TIMESTAMPTZ '2026-01-01 00:00:00Z' ELSE TIMESTAMPTZ '2026-01-02 00:00:00Z' END \
             WHERE id IN ($1, $2)",
        )
        .bind(older_id)
        .bind(newer_id)
        .execute(&pool.sqlx_pool())
        .await?;
        let finish = send(
            &first_router,
            Method::PATCH,
            &item_path(accepted_id),
            Some(r#"{"finished":true}"#),
            Some("\"v1\""),
        )
        .await?;
        assert_eq!(finish.status(), StatusCode::OK);
        assert_eq!(
            finish.headers().get(ETAG),
            Some(&HeaderValue::from_static("\"v2\""))
        );
        assert_eq!(json_body(finish).await?["version"], 2);

        let listed =
            json_body(send(&first_router, Method::GET, COLLECTION_PATH, None, None).await?).await?;
        let listed = listed
            .as_array()
            .ok_or("reading-item list was not an array")?;
        assert_eq!(listed.len(), 3);
        assert_eq!(value_id(&listed[0])?, newer_id);
        assert_eq!(value_id(&listed[1])?, older_id);
        assert_eq!(value_id(&listed[2])?, accepted_id);
        let second_list =
            json_body(send(&second_router, Method::GET, COLLECTION_PATH, None, None).await?)
                .await?;
        assert_eq!(second_list.as_array().map(Vec::len), Some(1));

        for malformed in ["*", "W/\"v1\"", "\"v1\", \"v2\"", "garbage"] {
            let response = send(
                &first_router,
                Method::PATCH,
                &item_path(older_id),
                Some(r#"{"finished":true}"#),
                Some(malformed),
            )
            .await?;
            assert_problem(response, StatusCode::BAD_REQUEST, "INVALID_IF_MATCH").await?;
        }
        let missing = send(
            &first_router,
            Method::PATCH,
            &item_path(older_id),
            Some(r#"{"finished":true}"#),
            None,
        )
        .await?;
        assert_problem(
            missing,
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
        )
        .await?;
        let stale = send(
            &first_router,
            Method::PATCH,
            &item_path(accepted_id),
            Some(r#"{"finished":false}"#),
            Some("\"v1\""),
        )
        .await?;
        assert_problem(
            stale,
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
        )
        .await?;
        let delete_missing = send(
            &first_router,
            Method::DELETE,
            &item_path(older_id),
            None,
            None,
        )
        .await?;
        assert_problem(
            delete_missing,
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
        )
        .await?;
        let delete_malformed = send(
            &first_router,
            Method::DELETE,
            &item_path(older_id),
            None,
            Some("W/\"v1\""),
        )
        .await?;
        assert_problem(
            delete_malformed,
            StatusCode::BAD_REQUEST,
            "INVALID_IF_MATCH",
        )
        .await?;
        let delete_stale = send(
            &first_router,
            Method::DELETE,
            &item_path(accepted_id),
            None,
            Some("\"v1\""),
        )
        .await?;
        assert_problem(
            delete_stale,
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
        )
        .await?;

        for method in [Method::PATCH, Method::DELETE] {
            let response = send(
                &second_router,
                method,
                &item_path(older_id),
                Some(r#"{"finished":true}"#),
                Some("\"v1\""),
            )
            .await?;
            assert_problem(response, StatusCode::NOT_FOUND, "READING_ITEM_NOT_FOUND").await?;
        }

        let reconstructed = principal_router(pool.clone(), first.clone());
        let persisted =
            json_body(send(&reconstructed, Method::GET, COLLECTION_PATH, None, None).await?)
                .await?;
        assert_eq!(persisted.as_array().map(Vec::len), Some(3));
        let deleted = send(
            &reconstructed,
            Method::DELETE,
            &item_path(older_id),
            None,
            Some("\"v1\""),
        )
        .await?;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let deleted_again = send(
            &reconstructed,
            Method::DELETE,
            &item_path(older_id),
            None,
            Some("\"v1\""),
        )
        .await?;
        assert_problem(
            deleted_again,
            StatusCode::NOT_FOUND,
            "READING_ITEM_NOT_FOUND",
        )
        .await?;

        sqlx::query("DELETE FROM reading_items WHERE owner_id = $1")
            .bind(first.subject_id.as_uuid())
            .execute(&pool.sqlx_pool())
            .await?;
        let mut transaction = pool.sqlx_pool().begin().await?;
        for index in 0..499_u16 {
            sqlx::query(
                "INSERT INTO reading_items (id, owner_id, title, url) VALUES ($1, $2, $3, $4)",
            )
            .bind(Uuid::now_v7())
            .bind(first.subject_id.as_uuid())
            .bind(format!("Seed {index}"))
            .bind(format!("https://seed.example/{index}"))
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        let left_router = reconstructed.clone();
        let right_router = reconstructed.clone();
        let (left, right) = tokio::join!(
            create(&left_router, "Concurrent left", "https://example.com/left"),
            create(
                &right_router,
                "Concurrent right",
                "https://example.com/right"
            )
        );
        let left = left?;
        let right = right?;
        let statuses = [left.status(), right.status()];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            1
        );
        let conflict = if left.status() == StatusCode::CONFLICT {
            left
        } else {
            right
        };
        assert_problem(
            conflict,
            StatusCode::CONFLICT,
            "READING_LIST_CAPACITY_EXCEEDED",
        )
        .await?;
        let final_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reading_items WHERE owner_id = $1")
                .bind(first.subject_id.as_uuid())
                .fetch_one(&pool.sqlx_pool())
                .await?;
        assert_eq!(final_count, 500);

        fixture.cleanup().await?;
        Ok(())
    }

    #[test]
    fn database_errors_are_classified_without_exposing_unexpected_failures() {
        let request_id = RequestId::new();
        assert_eq!(
            map_sqlx_error(&sqlx::Error::PoolClosed, request_id).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            map_sqlx_error(
                &sqlx::Error::Protocol("connection lost".to_owned()),
                request_id
            )
            .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            map_sqlx_error(&sqlx::Error::RowNotFound, request_id).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            map_sqlx_error(
                &sqlx::Error::Decode(std::io::Error::other("unexpected persisted value").into()),
                request_id
            )
            .status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    fn postgres_config(url: SecretString) -> PostgresConfig {
        PostgresConfig {
            url,
            tls_mode: PostgresTlsMode::Disable,
            min_connections: 1,
            max_connections: 4,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(60),
            max_lifetime_jitter: Duration::from_secs(10),
            application_name: "reading-list-test".to_owned(),
            initialization_sql: Vec::new(),
            statement_timeout: Duration::from_secs(10),
            lock_timeout: Duration::from_secs(2),
            health_timeout: Duration::from_secs(3),
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

    fn test_principal() -> TestResult<Principal> {
        let subject_id = SubjectId::from_uuid(Uuid::now_v7())?;
        Ok(Principal::new(
            subject_id,
            PrincipalKind::User,
            None,
            AuthMethod::Session,
            OffsetDateTime::now_utc(),
            AssuranceLevel::Aal1,
            Vec::new(),
        )?)
    }

    async fn seed_user(pool: &PostgresPool, principal: &Principal) -> TestResult {
        sqlx::query(
            "INSERT INTO users (id, status, created_at) VALUES ($1, 'active', clock_timestamp())",
        )
        .bind(principal.subject_id.as_uuid())
        .execute(&pool.sqlx_pool())
        .await?;
        Ok(())
    }

    fn principal_router(pool: PostgresPool, principal: Principal) -> Router {
        router(pool).layer(ServiceBuilder::new().layer(Extension(principal)))
    }

    async fn create(router: &Router, title: &str, url: &str) -> TestResult<Response> {
        let body = serde_json::to_string(&json!({"title": title, "url": url}))?;
        send(router, Method::POST, COLLECTION_PATH, Some(&body), None).await
    }

    async fn send(
        router: &Router,
        method: Method,
        uri: &str,
        body: Option<&str>,
        if_match: Option<&str>,
    ) -> TestResult<Response> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, JSON_CONTENT_TYPE);
        }
        if let Some(value) = if_match {
            builder = builder.header(IF_MATCH, value);
        }
        let request =
            builder.body(body.map_or_else(Body::empty, |value| Body::from(value.to_owned())))?;
        Ok(router.clone().oneshot(request).await?)
    }

    async fn json_body(response: Response) -> TestResult<Value> {
        Ok(serde_json::from_slice(
            &response.into_body().collect().await?.to_bytes(),
        )?)
    }

    async fn assert_problem(response: Response, status: StatusCode, code: &str) -> TestResult {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = json_body(response).await?;
        assert_eq!(body["code"], code);
        assert_eq!(body["status"], u64::from(status.as_u16()));
        Ok(())
    }

    fn value_id(value: &Value) -> TestResult<Uuid> {
        Ok(Uuid::parse_str(
            value["id"]
                .as_str()
                .ok_or("reading item did not contain an id")?,
        )?)
    }

    fn item_path(id: Uuid) -> String {
        format!("/api/reading-items/{id}")
    }
}
