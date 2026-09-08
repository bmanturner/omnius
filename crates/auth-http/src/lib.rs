//! Reusable account, browser-session, and canonical-principal HTTP composition.

#![forbid(unsafe_code)]

pub mod account_auth;
pub mod api_key_auth;
pub mod browser_auth;
mod composition;
mod config;
mod openapi;

use axum::{
    extract::{Extension, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use omnius_core::{ErrorCode, RequestId, ServiceError};
use omnius_http::ProblemDetails;
use utoipa::ToSchema;

pub use composition::{
    AuthenticatedHttpBuildError, AuthenticatedHttpInput, AuthenticatedHttpRuntime,
    AuthenticatedHttpRuntimeParts, build_authenticated_http,
};
#[cfg(feature = "api-key")]
pub use config::ApiKeyApplicationConfig;
pub use config::{
    AccountEmailConfig, AuthenticatedHttpConfig, AuthenticatedHttpConfigError, PasswordConfig,
    PasswordPepperConfig, RegistrationConfig,
};
#[cfg(feature = "api-key")]
pub use openapi::{
    API_KEY_MANAGEMENT_OPERATIONS, API_KEY_MANAGEMENT_ROUTE_IDS,
    api_key_management_openapi_contribution,
};
pub use openapi::{AUTH_HTTP_OPERATIONS, auth_openapi_contribution};

#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
pub(crate) struct ProblemFieldErrorSchema {
    #[schema(pattern = r"^(|/(?:[^~/]|~[01])*)$")]
    pointer: String,
    #[schema(pattern = r"^[a-z][a-z0-9_]*$")]
    code: String,
    #[schema(min_length = 1)]
    message: String,
}

#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
pub(crate) struct ProblemDetailsSchema {
    #[schema(format = "uri", example = "https://errors.omnius.invalid/internal")]
    r#type: String,
    #[schema(min_length = 1)]
    title: String,
    #[schema(minimum = 400, maximum = 599)]
    status: u16,
    #[schema(pattern = r"^[A-Z][A-Z0-9_]{0,63}$")]
    code: String,
    #[schema(format = Uuid)]
    request_id: String,
    detail: Option<String>,
    #[schema(max_items = 100)]
    errors: Option<Vec<ProblemFieldErrorSchema>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
}

impl ApiError {
    pub(crate) const fn new(
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

    pub(crate) const fn internal(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "an internal service error occurred",
            request_id,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let Ok(code) = ErrorCode::try_new(self.code) else {
            unreachable!("static API error code is valid");
        };
        let error = ServiceError::new(code, self.detail);
        let Ok(problem) = ProblemDetails::from_service_error(self.status, &error, self.request_id)
        else {
            unreachable!("API errors always use HTTP error statuses");
        };
        problem.into_response()
    }
}

pub(crate) fn resolve_request_id(extension: Option<Extension<RequestId>>) -> RequestId {
    extension.map_or_else(RequestId::new, |Extension(request_id)| request_id)
}

pub(crate) fn map_json_rejection(error: &JsonRejection, request_id: RequestId) -> ApiError {
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
            "request body must be valid JSON",
            request_id,
        ),
    }
}
