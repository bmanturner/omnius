//! Authenticated tenant-selection routes over the authoritative tenancy store.

use std::str::FromStr as _;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use omnius_auth_core::{Principal, SubjectId, TenantId};
use omnius_core::RequestId;
use omnius_http::ProblemDetails;
use omnius_tenancy::{MembershipRole, TenancyStore, TenancyStoreError, TenantContext};
use serde::Serialize;
use utoipa::ToSchema;

use super::browser_auth::{BrowserAuthSession, bind_browser_session_tenant};

/// Shared authoritative state for browser tenant-selection routes.
#[derive(Clone)]
pub struct BrowserTenancyState {
    tenancy: TenancyStore,
}

impl BrowserTenancyState {
    /// Builds browser tenant-selection state from the assembled tenancy provider.
    #[must_use]
    pub fn new(tenancy: TenancyStore) -> Self {
        Self { tenancy }
    }
}

/// Returns tenant-selection routes that must be wrapped by
/// `api_key_auth::protected_principal_router`.
pub fn browser_tenancy_router(state: BrowserTenancyState) -> Router {
    Router::new()
        .route("/tenants", get(list_tenants))
        .route("/tenants/{tenant_id}/switch", post(switch_tenant))
        .with_state(state)
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TenantSummary {
    #[schema(value_type = String, format = Uuid)]
    tenant_id: TenantId,
    name: String,
    permission_scope: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TenantSwitchMetadata {
    #[schema(value_type = String, format = Uuid)]
    tenant_id: TenantId,
    #[schema(value_type = String, format = Uuid)]
    principal_id: SubjectId,
    role: &'static str,
    grant_version: i64,
}

async fn list_tenants(
    State(state): State<BrowserTenancyState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Json<Vec<TenantSummary>>, BrowserTenancyHttpError> {
    let request_id = resolve_request_id(request_id);
    list_tenant_summaries(&state.tenancy, &principal, request_id)
        .await
        .map(Json)
}

async fn switch_tenant(
    State(state): State<BrowserTenancyState>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    Path(tenant): Path<String>,
) -> Result<Json<TenantSwitchMetadata>, BrowserTenancyHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = parse_tenant_id(&tenant, request_id)?;
    let context = resolve_switch_context(&state.tenancy, &principal, tenant_id, request_id).await?;
    bind_browser_session_tenant(&auth, tenant_id)
        .await
        .map_err(|_| BrowserTenancyHttpError::unavailable(request_id))?;
    Ok(Json(tenant_switch_metadata(&context)))
}

fn tenantless_principal(principal: &Principal) -> Principal {
    let mut canonical = principal.clone();
    canonical.tenant_id = None;
    canonical
}

async fn list_tenant_summaries(
    tenancy: &TenancyStore,
    principal: &Principal,
    request_id: RequestId,
) -> Result<Vec<TenantSummary>, BrowserTenancyHttpError> {
    let canonical = tenantless_principal(principal);
    let organizations = tenancy
        .list_organizations(canonical.subject_id)
        .await
        .map_err(|error| BrowserTenancyHttpError::from_tenancy(error, request_id))?;
    let mut summaries = Vec::with_capacity(organizations.len());
    for organization in organizations {
        let context = tenancy
            .resolve_tenant_context(&canonical, organization.id)
            .await
            .map_err(|error| BrowserTenancyHttpError::from_tenancy(error, request_id))?;
        summaries.push(TenantSummary {
            tenant_id: organization.id,
            name: organization.name.to_string(),
            permission_scope: context.membership().grant_version.to_string(),
        });
    }
    Ok(summaries)
}

async fn resolve_switch_context(
    tenancy: &TenancyStore,
    principal: &Principal,
    tenant_id: TenantId,
    request_id: RequestId,
) -> Result<TenantContext, BrowserTenancyHttpError> {
    let canonical = tenantless_principal(principal);
    tenancy
        .resolve_tenant_context(&canonical, tenant_id)
        .await
        .map_err(|error| BrowserTenancyHttpError::from_tenancy(error, request_id))
}

fn tenant_switch_metadata(context: &TenantContext) -> TenantSwitchMetadata {
    let membership = context.membership();
    TenantSwitchMetadata {
        tenant_id: membership.organization_id,
        principal_id: context.principal().subject_id,
        role: match membership.role {
            MembershipRole::Owner => "owner",
            MembershipRole::Admin => "admin",
            MembershipRole::Member => "member",
        },
        grant_version: membership.grant_version,
    }
}

fn parse_tenant_id(
    value: &str,
    request_id: RequestId,
) -> Result<TenantId, BrowserTenancyHttpError> {
    TenantId::from_str(value).map_err(|_| BrowserTenancyHttpError::bad_request(request_id))
}

#[derive(Clone, Copy, Debug)]
struct BrowserTenancyHttpError {
    status: StatusCode,
    request_id: RequestId,
}

impl BrowserTenancyHttpError {
    const fn bad_request(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            request_id,
        }
    }

    const fn unavailable(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            request_id,
        }
    }

    const fn from_tenancy(error: TenancyStoreError, request_id: RequestId) -> Self {
        let status = match error {
            TenancyStoreError::AccessDenied
            | TenancyStoreError::TenantMismatch
            | TenancyStoreError::MembershipNotFound
            | TenancyStoreError::UserNotFound => StatusCode::NOT_FOUND,
            TenancyStoreError::Unavailable | TenancyStoreError::Transient(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            TenancyStoreError::Conflict
            | TenancyStoreError::MembershipAlreadyActive
            | TenancyStoreError::InvalidMembershipTransition
            | TenancyStoreError::LastOwner
            | TenancyStoreError::InvitationAlreadyPending
            | TenancyStoreError::InvitationUnavailable
            | TenancyStoreError::InvitationExpired => StatusCode::CONFLICT,
            TenancyStoreError::InvalidInvitationExpiry | TenancyStoreError::ListLimitExceeded => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self { status, request_id }
    }
}

impl IntoResponse for BrowserTenancyHttpError {
    fn into_response(self) -> Response {
        match ProblemDetails::try_for_status(self.status, self.request_id) {
            Ok(problem) => problem.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

fn resolve_request_id(extension: Option<Extension<RequestId>>) -> RequestId {
    extension.map_or_else(RequestId::new, |Extension(request_id)| request_id)
}
