use std::sync::LazyLock;

use axum::{
    Json, Router,
    http::{HeaderValue, header::CACHE_CONTROL},
    response::{IntoResponse as _, Response},
    routing::get,
};
use omnius_realtime_core::{PING_ACTION, SUBSCRIBE_ACTION, UNSUBSCRIBE_ACTION};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use utoipa::ToSchema;

/// Schema version shared by the generated public metadata contracts.
pub const CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
/// Public API contract version reported to browser consumers.
pub const PUBLIC_API_VERSION: &str = "0.1.0";
/// Deterministic reference profile represented by the committed contracts.
pub const PUBLIC_PROFILE: &str = "full-reference-web";
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
const WEBSOCKET_TRANSPORT: &str = "/realtime/ws";
const SSE_TRANSPORT: &str = "/events";
const COMMITTED_OPENAPI: &[u8] = include_bytes!("../../../contracts/openapi.json");
const COMMITTED_ASYNCAPI: &[u8] = include_bytes!("../../../contracts/asyncapi.json");
const COMMITTED_PERMISSIONS: &[u8] = include_bytes!("../../../contracts/permissions.json");
const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Stable identifiers for browser-command permissions selected by the public profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicPermissionId {
    /// Send a heartbeat over an authenticated realtime connection.
    RealtimePing,
    /// Create an authenticated realtime subscription.
    RealtimeSubscriptionCreate,
    /// Delete an authenticated realtime subscription.
    RealtimeSubscriptionDelete,
}

impl PublicPermissionId {
    const fn descriptor(self) -> PublicPermission {
        match self {
            Self::RealtimePing => PublicPermission {
                id: PING_ACTION,
                description: "Send a heartbeat over the authenticated realtime connection.",
                resource: "realtime_connection",
                action: PING_ACTION,
                group: Some("realtime"),
                deprecated: false,
                replacement: None,
            },
            Self::RealtimeSubscriptionCreate => PublicPermission {
                id: SUBSCRIBE_ACTION,
                description: "Create an authorized subscription to a public realtime topic.",
                resource: "realtime_subscription",
                action: SUBSCRIBE_ACTION,
                group: Some("realtime"),
                deprecated: false,
                replacement: None,
            },
            Self::RealtimeSubscriptionDelete => PublicPermission {
                id: UNSUBSCRIBE_ACTION,
                description: "Delete an authorized subscription owned by the realtime connection.",
                resource: "realtime_subscription",
                action: UNSUBSCRIBE_ACTION,
                group: Some("realtime"),
                deprecated: false,
                replacement: None,
            },
        }
    }
}

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

const PUBLIC_PERMISSIONS: [PublicPermission; 3] = [
    PublicPermissionId::RealtimePing.descriptor(),
    PublicPermissionId::RealtimeSubscriptionCreate.descriptor(),
    PublicPermissionId::RealtimeSubscriptionDelete.descriptor(),
];

const SELECTED_BROWSER_COMMAND_ACTIONS: [&str; 3] =
    [PING_ACTION, SUBSCRIBE_ACTION, UNSUBSCRIBE_ACTION];

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

/// Stable structural browser capabilities compiled into the selected profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicCapabilityId {
    /// Browser authentication and canonical identity.
    WebAuth,
    /// Typed WebSocket and SSE consumption.
    WebRealtime,
    /// Browser upload workflows backed by public HTTP contracts.
    WebUploads,
}

impl PublicCapabilityId {
    const fn descriptor(self) -> PublicCapability {
        match self {
            Self::WebAuth => PublicCapability {
                id: "web-auth",
                compiled: true,
                runtime_available: true,
                minimum_sdk_version: MINIMUM_SDK_VERSION,
                auth_modes: &[AuthMode::Bearer, AuthMode::OidcRedirect, AuthMode::Session],
            },
            Self::WebRealtime => PublicCapability {
                id: "web-realtime",
                compiled: true,
                runtime_available: true,
                minimum_sdk_version: MINIMUM_SDK_VERSION,
                auth_modes: &[AuthMode::Session],
            },
            Self::WebUploads => PublicCapability {
                id: "web-uploads",
                compiled: true,
                runtime_available: true,
                minimum_sdk_version: MINIMUM_SDK_VERSION,
                auth_modes: &[AuthMode::Session],
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuthMode {
    Bearer,
    OidcRedirect,
    Session,
}

/// One structural capability descriptor, separate from deployment availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PublicCapability {
    id: &'static str,
    compiled: bool,
    runtime_available: bool,
    minimum_sdk_version: &'static str,
    auth_modes: &'static [AuthMode],
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

const PUBLIC_CAPABILITIES: [PublicCapability; 3] = [
    PublicCapabilityId::WebAuth.descriptor(),
    PublicCapabilityId::WebRealtime.descriptor(),
    PublicCapabilityId::WebUploads.descriptor(),
];
const PUBLIC_CAPABILITY_IDS: [&str; 3] = ["web-auth", "web-realtime", "web-uploads"];

/// Returns the sorted structural capability registry for the assembled contract profile.
#[must_use]
pub const fn public_capabilities() -> &'static [PublicCapability] {
    &PUBLIC_CAPABILITIES
}

/// Exact public transport locations shared by generated and runtime metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct PublicTransports {
    api: &'static str,
    websocket: Option<&'static str>,
    sse: Option<&'static str>,
}

/// Returns the public transport descriptor.
#[must_use]
pub const fn public_transports() -> PublicTransports {
    PublicTransports {
        api: API_TRANSPORT,
        websocket: Some(WEBSOCKET_TRANSPORT),
        sse: Some(SSE_TRANSPORT),
    }
}

/// Deterministically resolved modules for the explicit `full-reference-web` composition target.
pub const PUBLIC_PROFILE_MODULES: &[&str] = &[
    "admin",
    "asyncapi-contracts",
    "audit",
    "auth-api-key",
    "auth-core",
    "auth-jwt",
    "auth-oidc",
    "auth-password",
    "auth-session-postgres",
    "auth-totp",
    "auth-webauthn",
    "authz-basic",
    "billing",
    "cache-redis",
    "config",
    "consent",
    "consumer-contracts",
    "core",
    "data-lifecycle",
    "email",
    "events-nats",
    "feature-flags",
    "generator",
    "graphql",
    "grpc",
    "health",
    "http",
    "idempotency",
    "inbox",
    "jobs-apalis-redis",
    "jobs-core",
    "localization",
    "migrations",
    "moderation",
    "notifications",
    "object-storage",
    "openapi",
    "outbound-http",
    "outbox",
    "postgres",
    "rate-limit-local",
    "realtime-core",
    "redis-core",
    "runtime",
    "scheduler",
    "search-meilisearch",
    "sse",
    "telemetry",
    "tenancy",
    "test-support",
    "validation",
    "web-auth",
    "web-authorization",
    "web-feature-flags",
    "web-forms",
    "web-local-state",
    "web-react",
    "web-realtime",
    "web-sdk-core",
    "web-static",
    "web-tenancy",
    "web-testing",
    "web-uploads",
    "webhooks-inbound",
    "webhooks-svix",
    "websockets",
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
/// `contracts/asyncapi.json`, `contracts/openapi.json`, then `contracts/permissions.json`.
/// `capabilities.json` is excluded because it contains the aggregate.
#[must_use]
pub fn aggregate_contract_sha256(openapi: &[u8], asyncapi: &[u8], permissions: &[u8]) -> String {
    let mut digest = Sha256::new();
    for bytes in [asyncapi, openapi, permissions] {
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

/// Returns a stateless router exposing minimally sensitive public contract metadata.
pub fn metadata_router() -> Router {
    Router::new().route(PUBLIC_METADATA_PATH, get(runtime_metadata))
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RuntimeMetadataResponse {
    application_version: &'static str,
    api_version: &'static str,
    #[schema(pattern = r"^sha256:[0-9a-f]{64}$")]
    contract_hash: String,
    capabilities: &'static [&'static str],
    transports: PublicTransports,
    profile: &'static str,
    build_revision: &'static str,
}

static RUNTIME_METADATA: LazyLock<RuntimeMetadataResponse> =
    LazyLock::new(|| RuntimeMetadataResponse {
        application_version: env!("CARGO_PKG_VERSION"),
        api_version: PUBLIC_API_VERSION,
        contract_hash: format!(
            "sha256:{}",
            aggregate_contract_sha256(COMMITTED_OPENAPI, COMMITTED_ASYNCAPI, COMMITTED_PERMISSIONS,)
        ),
        capabilities: &PUBLIC_CAPABILITY_IDS,
        transports: public_transports(),
        profile: PUBLIC_PROFILE,
        build_revision: BUILD_REVISION,
    });

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
pub(crate) async fn runtime_metadata() -> Response {
    let mut response = Json(runtime_metadata_response()).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn runtime_metadata_response() -> &'static RuntimeMetadataResponse {
    &RUNTIME_METADATA
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
