use std::collections::BTreeSet;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, header::CACHE_CONTROL},
    response::{IntoResponse as _, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use utoipa::ToSchema;

/// Schema version shared by the generated public metadata contracts.
pub const CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
/// Public API contract version reported to browser consumers.
pub const PUBLIC_API_VERSION: &str = "0.1.0";
/// Deterministic reference profile represented by the committed contracts.
pub const PUBLIC_PROFILE: &str = "oauth-provider";
/// Oldest SDK version compatible with this contract set.
pub const MINIMUM_SDK_VERSION: &str = "0.1.0";
/// Minimally sensitive public runtime metadata endpoint.
pub const PUBLIC_METADATA_PATH: &str = "/api/_meta";
/// Reproducible build revision, supplied by CI when available.
pub const BUILD_REVISION: &str = match option_env!("OMNIUS_GIT_REVISION") {
    Some(revision) => revision,
    None => "reproducible",
};

const API_TRANSPORT: &str = "/api";
const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Stable identifiers for browser-command permissions selected by the public profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicPermissionId {}

/// One public authorization vocabulary entry derived from a backend action constant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PublicPermission {
    id: &'static str,
    description: &'static str,
    resource: &'static str,
    action: &'static str,
    group: Option<&'static str>,
    deprecated: bool,
    replacement: Option<&'static str>,
}

impl PublicPermission {
    /// Returns the stable public permission identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        self.id
    }

    /// Returns the authoritative backend authorization action.
    #[must_use]
    pub const fn action(self) -> &'static str {
        self.action
    }

    /// Returns the public resource class without policy or relationship facts.
    #[must_use]
    pub const fn resource(self) -> &'static str {
        self.resource
    }
}

const PUBLIC_PERMISSIONS: [PublicPermission; 0] = [];

const SELECTED_BROWSER_COMMAND_ACTIONS: [&str; 0] = [];

/// Returns the sorted public permission registry for the assembled contract profile.
#[must_use]
pub const fn public_permissions() -> &'static [PublicPermission] {
    &PUBLIC_PERMISSIONS
}

/// Returns every backend browser-command action that the public registry must cover.
#[must_use]
pub const fn selected_browser_command_actions() -> &'static [&'static str] {
    &SELECTED_BROWSER_COMMAND_ACTIONS
}

/// Stable structural public capabilities compiled into the selected profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicCapabilityId {
    /// First-party OAuth Authorization Server and `OpenID` Provider.
    OAuthIssuer,
    /// Browser authentication and canonical identity.
    WebAuth,
}

impl PublicCapabilityId {
    const fn descriptor(self) -> PublicCapability {
        match self {
            Self::OAuthIssuer => PublicCapability {
                id: "auth-oauth-server",
                compiled: true,
                runtime_available: true,
                minimum_sdk_version: MINIMUM_SDK_VERSION,
                auth_modes: &[AuthMode::Bearer, AuthMode::Session],
                auth_roles: &[
                    AuthRole::OauthAuthorizationServer,
                    AuthRole::OauthResourceServer,
                    AuthRole::OpenidProvider,
                ],
            },
            Self::WebAuth => PublicCapability {
                id: "web-auth",
                compiled: false,
                runtime_available: false,
                minimum_sdk_version: MINIMUM_SDK_VERSION,
                auth_modes: &[],
                auth_roles: &[],
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuthMode {
    Bearer,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuthRole {
    OauthAuthorizationServer,
    OauthResourceServer,
    OpenidProvider,
}

/// One structural capability descriptor, separate from deployment availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PublicCapability {
    id: &'static str,
    compiled: bool,
    runtime_available: bool,
    minimum_sdk_version: &'static str,
    auth_modes: &'static [AuthMode],
    auth_roles: &'static [AuthRole],
}

impl PublicCapability {
    /// Returns the stable public capability identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        self.id
    }

    /// Reports whether the selected profile structurally compiles the capability.
    #[must_use]
    pub const fn compiled(self) -> bool {
        self.compiled
    }

    /// Reports whether this reference binary assembles the capability's runtime adapter.
    #[must_use]
    pub const fn runtime_available(self) -> bool {
        self.runtime_available
    }
}

const PUBLIC_CAPABILITIES: [PublicCapability; 2] = [
    PublicCapabilityId::OAuthIssuer.descriptor(),
    PublicCapabilityId::WebAuth.descriptor(),
];
const PUBLIC_CAPABILITY_IDS: [&str; 1] = ["auth-oauth-server"];

/// Returns the sorted structural capability registry for the assembled contract profile.
#[must_use]
pub const fn public_capabilities() -> &'static [PublicCapability] {
    &PUBLIC_CAPABILITIES
}

/// Exact public transport locations shared by generated and runtime metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct PublicTransports {
    api: &'static str,
}

/// Returns the public transport descriptor.
#[must_use]
pub const fn public_transports() -> PublicTransports {
    PublicTransports { api: API_TRANSPORT }
}

/// Deterministically resolved modules for the explicit `oauth-provider` composition target.
pub const PUBLIC_PROFILE_MODULES: &[&str] = &[
    "audit",
    "auth-api-key",
    "auth-core",
    "auth-jwt",
    "auth-oauth-server",
    "auth-password",
    "auth-session-postgres",
    "authz-basic",
    "config",
    "core",
    "email",
    "generator",
    "health",
    "http",
    "idempotency",
    "jobs-core",
    "migrations",
    "openapi",
    "outbound-http",
    "postgres",
    "rate-limit-local",
    "runtime",
    "telemetry",
    "tenancy",
    "test-support",
    "validation",
];

/// Contract construction or serialization failed without reflecting document contents.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContractMetadataError {
    /// The public registry does not cover the selected backend actions exactly once.
    #[error("public permission registry does not cover selected backend actions")]
    PermissionRegistryCoverage,
    /// The aggregate hash was not a lowercase SHA-256 digest.
    #[error("contract aggregate hash is invalid")]
    InvalidAggregateHash,
    /// A generated capability contract was malformed or internally inconsistent.
    #[error("generated capability contract is invalid")]
    InvalidCapabilitiesContract,
    /// A static contract could not be serialized.
    #[error("contract metadata serialization failed")]
    Serialization,
}

#[derive(Serialize)]
struct PermissionsContract {
    schema_version: &'static str,
    permissions: &'static [PublicPermission],
}

#[derive(Serialize)]
struct CapabilitiesContract<'hash> {
    schema_version: &'static str,
    service_version: &'static str,
    profile: &'static str,
    contract_hash: &'hash str,
    capabilities: &'static [PublicCapability],
    transports: PublicTransports,
}

/// Serializes the canonical public permission artifact with a trailing newline.
///
/// # Errors
///
/// Returns [`ContractMetadataError`] if registry coverage or serialization fails.
pub fn permissions_contract_json() -> Result<Vec<u8>, ContractMetadataError> {
    ensure_permission_registry_coverage()?;
    canonical_json(&PermissionsContract {
        schema_version: CONTRACT_SCHEMA_VERSION,
        permissions: public_permissions(),
    })
}

/// Serializes the canonical public capability artifact with a trailing newline.
///
/// # Errors
///
/// Returns [`ContractMetadataError`] if the aggregate digest or serialization is invalid.
pub fn capabilities_contract_json(
    aggregate_sha256: &str,
) -> Result<Vec<u8>, ContractMetadataError> {
    if !is_sha256(aggregate_sha256) {
        return Err(ContractMetadataError::InvalidAggregateHash);
    }
    let contract_hash = format!("sha256:{aggregate_sha256}");
    canonical_json(&CapabilitiesContract {
        schema_version: CONTRACT_SCHEMA_VERSION,
        service_version: env!("CARGO_PKG_VERSION"),
        profile: PUBLIC_PROFILE,
        contract_hash: &contract_hash,
        capabilities: public_capabilities(),
        transports: public_transports(),
    })
}

/// Computes the aggregate SHA-256 over exact canonical leaf bytes.
///
/// Bytes are concatenated without separators in lexicographic path order:
/// `contracts/openapi.json`, then `contracts/permissions.json`.
/// `capabilities.json` is excluded because it contains the aggregate.
#[must_use]
pub fn aggregate_contract_sha256(openapi: &[u8], permissions: &[u8]) -> String {
    let mut digest = Sha256::new();
    for bytes in [openapi, permissions] {
        digest.update(bytes);
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct RuntimeTransports {
    api: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    websocket: Option<String>,
}

impl From<PublicTransports> for RuntimeTransports {
    fn from(transports: PublicTransports) -> Self {
        Self {
            api: transports.api.to_owned(),
            sse: None,
            websocket: None,
        }
    }
}

#[derive(Deserialize)]
struct GeneratedCapability {
    id: String,
    compiled: bool,
    runtime_available: bool,
}

#[derive(Deserialize)]
struct GeneratedCapabilitiesContract {
    profile: String,
    contract_hash: String,
    capabilities: Vec<GeneratedCapability>,
    transports: RuntimeTransports,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct RuntimeMetadataResponse {
    application_version: String,
    api_version: String,
    #[schema(pattern = r"^sha256:[0-9a-f]{64}$")]
    contract_hash: String,
    capabilities: Vec<String>,
    transports: RuntimeTransports,
    profile: String,
    build_revision: String,
}

/// Returns a stateless router exposing the checked-in reference metadata.
pub fn metadata_router(openapi: &[u8], permissions: &[u8]) -> Router {
    let metadata = RuntimeMetadataResponse {
        application_version: env!("CARGO_PKG_VERSION").to_owned(),
        api_version: PUBLIC_API_VERSION.to_owned(),
        contract_hash: format!("sha256:{}", aggregate_contract_sha256(openapi, permissions)),
        capabilities: PUBLIC_CAPABILITY_IDS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        transports: public_transports().into(),
        profile: PUBLIC_PROFILE.to_owned(),
        build_revision: BUILD_REVISION.to_owned(),
    };
    metadata_response_router(metadata)
}

/// Returns runtime metadata derived from a generated profile capability contract.
///
/// # Errors
///
/// Returns [`ContractMetadataError::InvalidCapabilitiesContract`] when the
/// generated artifact is malformed or claims an available uncompiled capability.
pub fn generated_metadata_router(
    capabilities: &[u8],
    application_version: &'static str,
) -> Result<Router, ContractMetadataError> {
    let contract: GeneratedCapabilitiesContract = serde_json::from_slice(capabilities)
        .map_err(|_| ContractMetadataError::InvalidCapabilitiesContract)?;
    let digest = contract
        .contract_hash
        .strip_prefix("sha256:")
        .ok_or(ContractMetadataError::InvalidCapabilitiesContract)?;
    if contract.profile.trim().is_empty()
        || !is_sha256(digest)
        || contract.transports.api != API_TRANSPORT
        || contract
            .transports
            .sse
            .as_deref()
            .is_some_and(|path| path != "/realtime/events")
        || contract
            .transports
            .websocket
            .as_deref()
            .is_some_and(|path| path != "/realtime/ws")
    {
        return Err(ContractMetadataError::InvalidCapabilitiesContract);
    }
    let mut ids = BTreeSet::new();
    let mut available = Vec::new();
    for capability in contract.capabilities {
        if capability.id.trim().is_empty()
            || !ids.insert(capability.id.clone())
            || (capability.runtime_available && !capability.compiled)
        {
            return Err(ContractMetadataError::InvalidCapabilitiesContract);
        }
        if capability.runtime_available {
            available.push(capability.id);
        }
    }
    Ok(metadata_response_router(RuntimeMetadataResponse {
        application_version: application_version.to_owned(),
        api_version: PUBLIC_API_VERSION.to_owned(),
        contract_hash: contract.contract_hash,
        capabilities: available,
        transports: contract.transports,
        profile: contract.profile,
        build_revision: BUILD_REVISION.to_owned(),
    }))
}

fn metadata_response_router(metadata: RuntimeMetadataResponse) -> Router {
    Router::new()
        .route(PUBLIC_METADATA_PATH, get(runtime_metadata))
        .with_state(metadata)
}

#[utoipa::path(
    get,
    path = "/api/_meta",
    operation_id = "getRuntimeMetadata",
    tag = "metadata",
    responses(
        (status = 200, description = "Minimally sensitive runtime contract metadata", body = RuntimeMetadataResponse, content_type = "application/json"),
        (status = 500, description = "Metadata unavailable", body = crate::ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
pub(crate) async fn runtime_metadata(State(metadata): State<RuntimeMetadataResponse>) -> Response {
    let mut response = Json(metadata).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn ensure_permission_registry_coverage() -> Result<(), ContractMetadataError> {
    if PUBLIC_PERMISSIONS.len() != SELECTED_BROWSER_COMMAND_ACTIONS.len()
        || PUBLIC_PERMISSIONS
            .iter()
            .zip(SELECTED_BROWSER_COMMAND_ACTIONS)
            .any(|(permission, action)| permission.action != action || permission.id != action)
    {
        return Err(ContractMetadataError::PermissionRegistryCoverage);
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractMetadataError> {
    let value = serde_json::to_value(value).map_err(|_| ContractMetadataError::Serialization)?;
    let mut bytes =
        serde_json::to_vec_pretty(&value).map_err(|_| ContractMetadataError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::{ContractMetadataError, generated_metadata_router};

    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn generated_metadata_accepts_profile_capabilities_and_realtime_transports() {
        let document = format!(
            r#"{{"profile":"realtime-web","contract_hash":"sha256:{DIGEST}","capabilities":[{{"id":"web-realtime","compiled":true,"runtime_available":true}}],"transports":{{"api":"/api","sse":"/realtime/events","websocket":"/realtime/ws"}}}}"#
        );
        assert!(generated_metadata_router(document.as_bytes(), "0.1.0").is_ok());
    }

    #[test]
    fn generated_metadata_rejects_available_uncompiled_capability() {
        let document = format!(
            r#"{{"profile":"web","contract_hash":"sha256:{DIGEST}","capabilities":[{{"id":"web-auth","compiled":false,"runtime_available":true}}],"transports":{{"api":"/api"}}}}"#
        );
        assert!(matches!(
            generated_metadata_router(document.as_bytes(), "0.1.0"),
            Err(ContractMetadataError::InvalidCapabilitiesContract)
        ));
    }
}
