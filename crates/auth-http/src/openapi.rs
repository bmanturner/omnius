use omnius_auth_password::RegistrationMode;
use omnius_http::ExpectedOperation;
use omnius_openapi::OpenApiError;
use serde_json::Value;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
#[cfg(feature = "jwt")]
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder};
use utoipa::{Modify, ToSchema};

#[cfg(feature = "api-key")]
use crate::api_key_auth;
use crate::{ProblemDetailsSchema, ProblemFieldErrorSchema};

const DEFAULT_SESSION_COOKIE_NAME: &str = "__Host-omnius_session";
const DISABLED_ROUTE_COUNT: usize = 13;
const SELF_SERVICE_ROUTE_COUNT: usize = 14;
const DISABLED_OPERATION_COUNT: usize = 13;
const SELF_SERVICE_OPERATION_COUNT: usize = 14;
pub(crate) const AUTH_HTTP_ROUTE_IDS: &[&str] = &[
    "/whoami",
    "/auth/login",
    "/auth/session",
    "/auth/logout",
    "/auth/logout-all",
    "/auth/permissions/privileged",
    "/auth/email/verification/request",
    "/auth/email/verification/complete",
    "/auth/password/reset/request",
    "/auth/password/reset/complete",
    "/auth/password/change",
    "/auth/sessions",
    "/auth/sessions/{device_id}",
    "/auth/register",
    "/auth/registration-invitations",
    "/auth/registration-invitations/{invitation_id}",
];

/// Exact core account, browser-session, and canonical-principal operations.
pub const AUTH_HTTP_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new("get", "/whoami", "getCurrentPrincipal", "identity"),
    ExpectedOperation::new(
        "post",
        "/auth/login",
        "loginBrowserSession",
        "authentication",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/session",
        "getBrowserSession",
        "authentication",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/logout",
        "logoutBrowserSession",
        "authentication",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/logout-all",
        "logoutAllBrowserSessions",
        "authentication",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/permissions/privileged",
        "checkPrivilegedBrowserPermission",
        "authorization",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/email/verification/request",
        "requestEmailVerification",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/email/verification/complete",
        "completeEmailVerification",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/password/reset/request",
        "requestPasswordReset",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/password/reset/complete",
        "completePasswordReset",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/password/change",
        "changePassword",
        "accounts",
    ),
    ExpectedOperation::new("get", "/auth/sessions", "listActiveSessions", "sessions"),
    ExpectedOperation::new(
        "delete",
        "/auth/sessions/{device_id}",
        "revokeSessionDevice",
        "sessions",
    ),
    ExpectedOperation::new("post", "/auth/register", "registerLocalAccount", "accounts"),
    ExpectedOperation::new(
        "post",
        "/auth/registration-invitations",
        "issueRegistrationInvitation",
        "registration-invitations",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/registration-invitations",
        "listRegistrationInvitations",
        "registration-invitations",
    ),
    ExpectedOperation::new(
        "delete",
        "/auth/registration-invitations/{invitation_id}",
        "revokeRegistrationInvitation",
        "registration-invitations",
    ),
];
#[must_use]
pub(crate) fn auth_http_route_ids(registration_mode: RegistrationMode) -> &'static [&'static str] {
    match registration_mode {
        RegistrationMode::Disabled => &AUTH_HTTP_ROUTE_IDS[..DISABLED_ROUTE_COUNT],
        RegistrationMode::SelfService => &AUTH_HTTP_ROUTE_IDS[..SELF_SERVICE_ROUTE_COUNT],
        RegistrationMode::InviteOnly => AUTH_HTTP_ROUTE_IDS,
    }
}

/// Returns the exact auth operations mounted for one registration policy.
#[must_use]
pub fn auth_http_operations_for(
    registration_mode: RegistrationMode,
) -> &'static [ExpectedOperation] {
    match registration_mode {
        RegistrationMode::Disabled => &AUTH_HTTP_OPERATIONS[..DISABLED_OPERATION_COUNT],
        RegistrationMode::SelfService => &AUTH_HTTP_OPERATIONS[..SELF_SERVICE_OPERATION_COUNT],
        RegistrationMode::InviteOnly => AUTH_HTTP_OPERATIONS,
    }
}
#[cfg(feature = "api-key")]
/// Exact API-key management route paths.
pub const API_KEY_MANAGEMENT_ROUTE_IDS: &[&str] = &[
    "/auth/service-accounts",
    "/auth/service-accounts/{service_account_id}",
    "/auth/service-accounts/{service_account_id}/api-keys",
    "/auth/api-keys/{api_key_id}/rotate",
    "/auth/api-keys/{api_key_id}",
];

#[cfg(feature = "api-key")]
/// Exact API-key management operations.
pub const API_KEY_MANAGEMENT_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new(
        "post",
        "/auth/service-accounts",
        "createServiceAccount",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/service-accounts",
        "listServiceAccounts",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/service-accounts/{service_account_id}",
        "getServiceAccount",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "delete",
        "/auth/service-accounts/{service_account_id}",
        "disableServiceAccount",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/service-accounts/{service_account_id}/api-keys",
        "issueServiceAccountApiKey",
        "api-keys",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/service-accounts/{service_account_id}/api-keys",
        "listServiceAccountApiKeys",
        "api-keys",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/api-keys/{api_key_id}/rotate",
        "rotateApiKey",
        "api-keys",
    ),
    ExpectedOperation::new(
        "delete",
        "/auth/api-keys/{api_key_id}",
        "revokeApiKey",
        "api-keys",
    ),
];

#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountRegisterRequestSchema {
    #[schema(format = Email)]
    email: String,
    #[schema(format = Password)]
    password: String,
    invitation: Option<String>,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountIdentityRequestSchema {
    #[schema(format = Email)]
    email: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountTokenCompletionRequestSchema {
    token: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountPasswordResetRequestSchema {
    token: String,
    #[schema(format = Password)]
    new_password: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountPasswordChangeRequestSchema {
    #[schema(format = Password)]
    current_password: String,
    #[schema(format = Password)]
    new_password: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountInvitationIssueRequestSchema {
    #[schema(format = Email)]
    email: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountAcceptedResponseSchema {
    status: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountSessionResponseSchema {
    #[schema(format = Uuid)]
    device_id: String,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    last_seen_at: String,
    #[schema(format = DateTime)]
    absolute_expires_at: String,
    current: bool,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountSessionListResponseSchema {
    sessions: Vec<AccountSessionResponseSchema>,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountInvitationResponseSchema {
    #[schema(format = Uuid)]
    id: String,
    #[schema(format = Email)]
    email: String,
    issuer_kind: String,
    issuer_id: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    expires_at: String,
    #[schema(format = DateTime)]
    consumed_at: Option<String>,
    #[schema(format = DateTime)]
    revoked_at: Option<String>,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct AccountInvitationListResponseSchema {
    invitations: Vec<AccountInvitationResponseSchema>,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct BrowserLoginRequestSchema {
    identifier: String,
    #[schema(format = Password)]
    password: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct BrowserResourcePermissionSchema {
    permission: String,
    context: Value,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct BrowserTenantSchema {
    #[schema(format = Uuid)]
    id: String,
}
#[expect(dead_code, reason = "OpenAPI schema carrier")]
#[derive(ToSchema)]
struct BrowserSessionResponseSchema {
    #[schema(format = Uuid)]
    subject_id: String,
    kind: String,
    #[schema(format = Uuid)]
    tenant_id: Option<String>,
    #[schema(format = DateTime)]
    authenticated_at: String,
    auth_method: String,
    assurance: String,
    scopes: Vec<String>,
    #[schema(format = DateTime)]
    expires_at: String,
    presentation_permissions: Vec<String>,
    resource_permissions: Vec<BrowserResourcePermissionSchema>,
    tenant: Option<BrowserTenantSchema>,
}

struct AuthenticationSecurity;
impl Modify for AuthenticationSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let Some(components) = openapi.components.as_mut() else {
            return;
        };
        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("__Host-omnius_session"))),
        );
        #[cfg(feature = "jwt")]
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
        #[cfg(feature = "api-key")]
        components.add_security_scheme(
            "api_key_auth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
        );
    }
}

macro_rules! auth_contract {
    ($name:ident, $method:ident, $path:literal, $operation:literal, $tag:literal, $($rest:tt)*) => {
        #[expect(dead_code, reason = "runtime route is implemented by auth HTTP handlers")]
        #[utoipa::path($method, path = $path, operation_id = $operation, tag = $tag, $($rest)*)]
        fn $name() {}
    };
}

auth_contract!(
    account_register_contract,
    post,
    "/auth/register",
    "registerLocalAccount",
    "accounts",
    request_body(
        content = AccountRegisterRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 202,
            description = "Enumeration-safe registration accepted",
            body = AccountAcceptedResponseSchema
        ),
        (
            status = 400,
            description = "Registration input or mode mismatch",
            body = ProblemDetailsSchema
        ),
        (
            status = 422,
            description = "Password policy rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Registration persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(())
);
auth_contract!(
    account_verification_request_contract,
    post,
    "/auth/email/verification/request",
    "requestEmailVerification",
    "accounts",
    request_body(
        content = AccountIdentityRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 202,
            description = "Enumeration-safe verification request accepted",
            body = AccountAcceptedResponseSchema
        ),
        (
            status = 400,
            description = "Invalid bounded identity",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Account persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(())
);
auth_contract!(
    account_verification_complete_contract,
    post,
    "/auth/email/verification/complete",
    "completeEmailVerification",
    "accounts",
    request_body(
        content = AccountTokenCompletionRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 204,
            description = "Email verified and pending account activated"
        ),
        (
            status = 400,
            description = "One-time token rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Account persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(())
);
auth_contract!(
    account_password_reset_request_contract,
    post,
    "/auth/password/reset/request",
    "requestPasswordReset",
    "accounts",
    request_body(
        content = AccountIdentityRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 202,
            description = "Enumeration-safe password reset request accepted",
            body = AccountAcceptedResponseSchema
        ),
        (
            status = 400,
            description = "Invalid bounded identity",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Account persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(())
);
auth_contract!(
    account_password_reset_complete_contract,
    post,
    "/auth/password/reset/complete",
    "completePasswordReset",
    "accounts",
    request_body(
        content = AccountPasswordResetRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 204,
            description = "Password replaced and all browser sessions revoked"
        ),
        (
            status = 400,
            description = "One-time token rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 422,
            description = "Password policy rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Account persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(())
);
auth_contract!(
    account_password_change_contract,
    post,
    "/auth/password/change",
    "changePassword",
    "accounts",
    request_body(
        content = AccountPasswordChangeRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 204,
            description = "Password changed and sessions rotated"
        ),
        (
            status = 401,
            description = "Session or password rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 422,
            description = "Password policy rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Account persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);
auth_contract!(
    account_sessions_contract,
    get,
    "/auth/sessions",
    "listActiveSessions",
    "sessions",
    responses(
        (
            status = 200,
            description = "Safe active-device session inventory",
            body = AccountSessionListResponseSchema
        ),
        (
            status = 401,
            description = "Active browser session required",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Session persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);
auth_contract!(
    account_session_revoke_contract,
    delete,
    "/auth/sessions/{device_id}",
    "revokeSessionDevice",
    "sessions",
    params(("device_id" = String, Path, format = Uuid)),
    responses(
        (status = 204, description = "Device session revoked"),
        (
            status = 400,
            description = "Invalid device identifier",
            body = ProblemDetailsSchema
        ),
        (
            status = 401,
            description = "Active browser session required",
            body = ProblemDetailsSchema
        ),
        (
            status = 404,
            description = "Active device not found",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Session persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);
auth_contract!(
    account_invitation_issue_contract,
    post,
    "/auth/registration-invitations",
    "issueRegistrationInvitation",
    "registration-invitations",
    request_body(
        content = AccountInvitationIssueRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (
            status = 201,
            description = "Invitation committed and delivered",
            body = AccountInvitationResponseSchema
        ),
        (
            status = 401,
            description = "Active browser session required",
            body = ProblemDetailsSchema
        ),
        (
            status = 403,
            description = "Invitation-management permission required",
            body = ProblemDetailsSchema
        ),
        (
            status = 409,
            description = "Active invitation exists",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Invitation unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []), ("bearer_auth" = []))
);
auth_contract!(account_invitations_contract, get, "/auth/registration-invitations", "listRegistrationInvitations", "registration-invitations", params(("limit" = Option<u16>, Query), ("before_created_at" = Option<String>, Query, format = DateTime), ("before_id" = Option<uuid::Uuid>, Query)), responses((status = 200, description = "Safe invitation metadata page", body = AccountInvitationListResponseSchema), (status = 400, description = "Invalid pagination input", body = ProblemDetailsSchema), (status = 401, description = "Active browser session required", body = ProblemDetailsSchema), (status = 403, description = "Invitation-management permission required", body = ProblemDetailsSchema), (status = 503, description = "Invitation persistence unavailable", body = ProblemDetailsSchema)), security(("session_cookie" = []), ("bearer_auth" = [])));
auth_contract!(
    account_invitation_revoke_contract,
    delete,
    "/auth/registration-invitations/{invitation_id}",
    "revokeRegistrationInvitation",
    "registration-invitations",
    params(("invitation_id" = String, Path, format = Uuid)),
    responses(
        (status = 204, description = "Pending invitation revoked"),
        (
            status = 400,
            description = "Invalid invitation identifier",
            body = ProblemDetailsSchema
        ),
        (
            status = 401,
            description = "Active browser session required",
            body = ProblemDetailsSchema
        ),
        (
            status = 403,
            description = "Invitation-management permission required",
            body = ProblemDetailsSchema
        ),
        (
            status = 404,
            description = "Pending invitation not found",
            body = ProblemDetailsSchema
        ),
        (
            status = 503,
            description = "Invitation persistence unavailable",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []), ("bearer_auth" = []))
);
auth_contract!(
    browser_login_contract,
    post,
    "/auth/login",
    "loginBrowserSession",
    "authentication",
    request_body(
        content = BrowserLoginRequestSchema,
        content_type = "application/json"
    ),
    responses(
        (status = 204, description = "Browser session established"),
        (
            status = 401,
            description = "Credentials rejected",
            body = ProblemDetailsSchema
        ),
        (
            status = 422,
            description = "Request validation failed",
            body = ProblemDetailsSchema
        )
    ),
    security(())
);
auth_contract!(
    browser_session_contract,
    get,
    "/auth/session",
    "getBrowserSession",
    "authentication",
    responses(
        (
            status = 200,
            description = "Current browser session",
            body = BrowserSessionResponseSchema
        ),
        (
            status = 401,
            description = "Session missing, expired, or revoked",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);
auth_contract!(
    browser_logout_contract,
    post,
    "/auth/logout",
    "logoutBrowserSession",
    "authentication",
    responses(
        (status = 204, description = "Current session revoked"),
        (
            status = 401,
            description = "Session missing, expired, or revoked",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);
auth_contract!(
    browser_logout_all_contract,
    post,
    "/auth/logout-all",
    "logoutAllBrowserSessions",
    "authentication",
    responses(
        (status = 204, description = "All subject sessions revoked"),
        (
            status = 401,
            description = "Session missing, expired, or revoked",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);
auth_contract!(
    browser_privileged_permission_contract,
    post,
    "/auth/permissions/privileged",
    "checkPrivilegedBrowserPermission",
    "authorization",
    responses(
        (status = 204, description = "Permission granted"),
        (
            status = 403,
            description = "Permission denied",
            body = ProblemDetailsSchema
        )
    ),
    security(("session_cookie" = []))
);

#[derive(utoipa::OpenApi)]
#[openapi(
    info(title = "Omnius Auth HTTP", version = "0.1.0"),
    paths(
        crate::api_key_auth::current_principal,
        account_register_contract, account_verification_request_contract,
        account_verification_complete_contract, account_password_reset_request_contract,
        account_password_reset_complete_contract, account_password_change_contract,
        account_sessions_contract, account_session_revoke_contract,
        account_invitation_issue_contract, account_invitations_contract,
        account_invitation_revoke_contract, browser_login_contract, browser_session_contract,
        browser_logout_contract, browser_logout_all_contract,
        browser_privileged_permission_contract
    ),
    components(schemas(
        crate::api_key_auth::PrincipalResponse,
        AccountRegisterRequestSchema, AccountIdentityRequestSchema,
        AccountTokenCompletionRequestSchema, AccountPasswordResetRequestSchema,
        AccountPasswordChangeRequestSchema, AccountInvitationIssueRequestSchema,
        AccountAcceptedResponseSchema, AccountSessionResponseSchema,
        AccountSessionListResponseSchema, AccountInvitationResponseSchema,
        AccountInvitationListResponseSchema, BrowserLoginRequestSchema,
        BrowserResourcePermissionSchema, BrowserTenantSchema, BrowserSessionResponseSchema,
        ProblemDetailsSchema, ProblemFieldErrorSchema
    )),
    modifiers(&AuthenticationSecurity)
)]
/// Typed `OpenAPI` document for core authentication routes.
struct AuthHttpDocument;

#[cfg(feature = "api-key")]
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        api_key_auth::create_service_account, api_key_auth::list_service_accounts,
        api_key_auth::get_service_account, api_key_auth::disable_service_account,
        api_key_auth::issue_api_key, api_key_auth::list_api_keys,
        api_key_auth::rotate_api_key, api_key_auth::revoke_api_key
    ),
    components(schemas(
        api_key_auth::CreateServiceAccountRequest, api_key_auth::IssueApiKeyRequest,
        api_key_auth::RotateApiKeyRequest, api_key_auth::ServiceAccountResponse,
        api_key_auth::ServiceAccountListResponse, api_key_auth::ApiKeyResponse,
        api_key_auth::ApiKeyListResponse, api_key_auth::CreatedApiKeyResponseSchema,
        ProblemDetailsSchema, ProblemFieldErrorSchema
    )),
    modifiers(&AuthenticationSecurity)
)]
struct ApiKeyDocument;

fn normalize_problem_content_types(responses: &mut serde_json::Map<String, Value>) {
    for response in responses.values_mut() {
        let Some(content) = response.get_mut("content").and_then(Value::as_object_mut) else {
            continue;
        };
        let is_problem = content
            .get("application/json")
            .and_then(|representation| representation.pointer("/schema/$ref"))
            .and_then(Value::as_str)
            == Some("#/components/schemas/ProblemDetailsSchema");
        if !is_problem {
            continue;
        }
        let Some(representation) = content.remove("application/json") else {
            continue;
        };
        content.insert("application/problem+json".to_owned(), representation);
    }
}
fn retain_registration_paths(
    document: &mut Value,
    registration_mode: RegistrationMode,
) -> Result<(), OpenApiError> {
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .ok_or(OpenApiError::SerializationFailed)?;
    if registration_mode == RegistrationMode::Disabled {
        let _ = paths.remove("/auth/register");
    }
    if registration_mode != RegistrationMode::InviteOnly {
        let _ = paths.remove("/auth/registration-invitations");
        let _ = paths.remove("/auth/registration-invitations/{invitation_id}");
    }
    Ok(())
}

fn finalize_document(
    mut document: Value,
    expected: &[ExpectedOperation],
    session_cookie_name: &str,
) -> Result<Value, OpenApiError> {
    let cookie_name = document
        .pointer_mut("/components/securitySchemes/session_cookie/name")
        .ok_or(OpenApiError::SerializationFailed)?;
    *cookie_name = Value::String(session_cookie_name.to_owned());
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .ok_or(OpenApiError::SerializationFailed)?;
    for path in paths.values_mut() {
        let operations = path
            .as_object_mut()
            .ok_or(OpenApiError::SerializationFailed)?;
        for operation in operations.values_mut() {
            let operation = operation
                .as_object_mut()
                .ok_or(OpenApiError::SerializationFailed)?;
            let responses = operation
                .get_mut("responses")
                .and_then(Value::as_object_mut)
                .ok_or(OpenApiError::SerializationFailed)?;
            normalize_problem_content_types(responses);
            responses.entry("default").or_insert_with(|| {
                serde_json::json!({
                    "description": "Problem details error response",
                    "content": {
                        "application/problem+json": {
                            "schema": {
                                "$ref": "#/components/schemas/ProblemDetailsSchema"
                            }
                        }
                    }
                })
            });
            if let Some(security) = operation.get_mut("security").and_then(Value::as_array_mut) {
                security.retain(|requirement| {
                    let Some(requirement) = requirement.as_object() else {
                        return false;
                    };
                    let _ = requirement;
                    #[cfg(not(feature = "jwt"))]
                    if requirement.contains_key("bearer_auth") {
                        return false;
                    }
                    #[cfg(not(feature = "api-key"))]
                    if requirement.contains_key("api_key_auth") {
                        return false;
                    }
                    true
                });
            }
        }
    }
    omnius_openapi::validate_operation_coverage_value(&document, expected)?;
    Ok(document)
}

/// Builds and validates the typed core authentication `OpenAPI` contribution.
///
/// # Errors
/// Returns [`OpenApiError`] when serialization or exact operation coverage validation fails.
pub fn auth_openapi_contribution() -> Result<Value, OpenApiError> {
    auth_openapi_contribution_for(DEFAULT_SESSION_COOKIE_NAME, RegistrationMode::InviteOnly)
}

/// Builds the typed core authentication `OpenAPI` contribution for an exact runtime policy.
///
/// # Errors
/// Returns [`OpenApiError`] when serialization or exact operation coverage validation fails.
pub fn auth_openapi_contribution_for(
    session_cookie_name: &str,
    registration_mode: RegistrationMode,
) -> Result<Value, OpenApiError> {
    let mut document = serde_json::to_value(<AuthHttpDocument as utoipa::OpenApi>::openapi())
        .map_err(|_| OpenApiError::SerializationFailed)?;
    retain_registration_paths(&mut document, registration_mode)?;
    finalize_document(
        document,
        auth_http_operations_for(registration_mode),
        session_cookie_name,
    )
}

#[cfg(feature = "api-key")]
/// Builds and validates the typed API-key management `OpenAPI` contribution.
///
/// # Errors
/// Returns [`OpenApiError`] when serialization or exact operation coverage validation fails.
pub fn api_key_management_openapi_contribution() -> Result<Value, OpenApiError> {
    let document = serde_json::to_value(<ApiKeyDocument as utoipa::OpenApi>::openapi())
        .map_err(|_| OpenApiError::SerializationFailed)?;
    finalize_document(
        document,
        API_KEY_MANAGEMENT_OPERATIONS,
        DEFAULT_SESSION_COOKIE_NAME,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Result<Value, OpenApiError> {
        auth_openapi_contribution()
    }

    #[test]
    fn preserves_typed_auth_contract_details() -> Result<(), OpenApiError> {
        let document = document()?;
        assert_eq!(
            document
                .pointer(
                    "/paths/~1auth~1register/post/requestBody/content/application~1json/schema/$ref"
                )
                .and_then(Value::as_str),
            Some("#/components/schemas/AccountRegisterRequestSchema")
        );
        assert!(
            document
                .pointer("/components/schemas/BrowserSessionResponseSchema/properties/expires_at")
                .is_some()
        );
        assert_eq!(
            document
                .pointer("/paths/~1auth~1sessions~1{device_id}/delete/parameters/0/name")
                .and_then(Value::as_str),
            Some("device_id")
        );
        assert_eq!(
            document
                .pointer(
                    "/paths/~1auth~1registration-invitations~1{invitation_id}/delete/parameters/0/in"
                )
                .and_then(Value::as_str),
            Some("path")
        );
        assert!(document.pointer("/paths/~1whoami/get/security").is_some());
        assert!(
            document
                .pointer("/paths/~1auth~1login/post/responses/200")
                .is_none()
        );
        assert!(
            document
                .pointer("/paths/~1auth~1login/post/responses/204")
                .is_some()
        );
        assert_eq!(
            document
                .pointer(
                    "/paths/~1auth~1login/post/responses/401/content/application~1problem+json/schema/$ref"
                )
                .and_then(Value::as_str),
            Some("#/components/schemas/ProblemDetailsSchema")
        );
        assert!(
            document
                .pointer("/paths/~1auth~1register/post/responses/400/content/application~1json")
                .is_none()
        );
        let mut documented = document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or(OpenApiError::SerializationFailed)?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        documented.sort_unstable();
        let mut mounted = AUTH_HTTP_ROUTE_IDS.to_vec();
        mounted.sort_unstable();
        assert_eq!(documented, mounted);
        Ok(())
    }
    #[test]
    fn policy_specific_contract_matches_registration_and_cookie_configuration()
    -> Result<(), OpenApiError> {
        let self_service =
            auth_openapi_contribution_for("reading_list_session", RegistrationMode::SelfService)?;
        assert_eq!(
            self_service
                .pointer("/components/securitySchemes/session_cookie/name")
                .and_then(Value::as_str),
            Some("reading_list_session")
        );
        assert!(self_service.pointer("/paths/~1auth~1register").is_some());
        assert!(
            self_service
                .pointer("/paths/~1auth~1registration-invitations")
                .is_none()
        );
        let mut documented = self_service["paths"]
            .as_object()
            .ok_or(OpenApiError::SerializationFailed)?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        documented.sort_unstable();
        let mut mounted = auth_http_route_ids(RegistrationMode::SelfService).to_vec();
        mounted.sort_unstable();
        assert_eq!(documented, mounted);

        let disabled =
            auth_openapi_contribution_for(DEFAULT_SESSION_COOKIE_NAME, RegistrationMode::Disabled)?;
        assert!(disabled.pointer("/paths/~1auth~1register").is_none());
        assert!(
            disabled
                .pointer("/paths/~1auth~1registration-invitations")
                .is_none()
        );
        Ok(())
    }

    #[cfg(feature = "api-key")]
    #[test]
    fn preserves_api_key_contract_details() -> Result<(), OpenApiError> {
        let document = api_key_management_openapi_contribution()?;
        assert!(document
            .pointer(
                "/paths/~1auth~1service-accounts~1{service_account_id}~1api-keys/post/requestBody"
            )
            .is_some());
        assert!(
            document
                .pointer("/components/schemas/CreatedApiKeyResponseSchema/properties/api_key")
                .is_some()
        );
        assert!(
            document
                .pointer("/components/securitySchemes/api_key_auth")
                .is_some()
        );
        let mut documented = document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or(OpenApiError::SerializationFailed)?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        documented.sort_unstable();
        let mut mounted = API_KEY_MANAGEMENT_ROUTE_IDS.to_vec();
        mounted.sort_unstable();
        assert_eq!(documented, mounted);
        Ok(())
    }
}
