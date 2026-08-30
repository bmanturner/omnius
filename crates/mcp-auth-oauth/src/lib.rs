//! MCP OAuth protected-resource security boundary.
//!
//! This crate owns canonical RFC 8707 resource identity, RFC 9728 metadata,
//! Authorization-header-only Bearer authentication, exact discovery challenges,
//! tenant and ordinary-authorization guards, and safe outbound capability-header
//! projection. It is transport-neutral and mounts no HTTP routes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bearer;
mod challenge;
mod guards;
mod headers;
mod resource;

pub use bearer::{
    BearerCredential, BearerPresentationError, BearerTokenAuthenticator, LiveStateRequirement,
    McpAuthenticatedIdentity, OAuthAccessTokenAuthenticator, TokenDecisionInput,
    authenticate_bearer_request, extract_bearer_credential,
};
pub use challenge::{BearerAuthenticationError, McpAuthRejection, WwwAuthenticate};
pub use guards::{
    CapabilityVisibility, McpOperation, McpOperationAuthorizer, OperationAuthorizationRequest,
    OperationAuthorized, OperationDenied, OperationGuard, TenantAuthorized, TenantGuard,
};
pub use headers::{
    MAX_MCP_HEADER_NAMES, MAX_MCP_HEADER_VALUE_BYTES, McpHeaderAllowlist, McpHeaderError,
    OutboundHeaderProjection,
};
pub use resource::{
    MAX_PROTECTED_RESOURCE_METADATA_BYTES, McpProtectedResource, McpProtectedResourceMetadata,
    McpResourceIdentity, OperationRequirements, PROTECTED_RESOURCE_METADATA_CACHE_CONTROL,
    PROTECTED_RESOURCE_METADATA_CONTENT_TYPE, PROTECTED_RESOURCE_METADATA_MAX_AGE_SECONDS,
    ProtectedResourceError,
};
