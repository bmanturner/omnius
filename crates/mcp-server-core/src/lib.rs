//! Stateless MCP dispatch over the canonical application capability registry.
//!
//! Application and composition code use only the SDK-free contracts exported from
//! this module. Omnius-owned transports terminate RMCP values in the hidden [`sdk`]
//! boundary before constructing canonical registry invocations.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod discovery;
mod extensions;
mod kernel;
mod metadata;
mod request;
mod versioning;

#[doc(hidden)]
pub mod sdk;

pub use discovery::{McpAuthorizedExposure, McpExposureAuthorizer, McpExposureFilter};
pub use extensions::{
    MAX_EXTENSION_REVISION_BYTES, MCP_EXTENSION_REVISION_KEY, McpExtension, McpExtensionCatalog,
    McpExtensionError, McpExtensionId, McpExtensionRevision, McpNegotiatedExtensions,
};
pub use kernel::{
    MCP_PROTOCOL_REVISION, McpDispatch, McpDispatchError, McpDispatchErrorCode, McpDispatchFuture,
    McpDispatchRequest, McpKernel, McpPrimitive,
};
pub use metadata::{
    MAX_CLIENT_CAPABILITIES, MAX_CLIENT_NAME_BYTES, MAX_CLIENT_VERSION_BYTES, MAX_EXTENSIONS,
    MAX_METADATA_IDENTIFIER_BYTES, McpClientIdentity, McpLogLevel, McpMetadataError,
    McpRequestMetadata,
};
pub use request::{McpCanonicalContext, McpRequestContext, McpRequestContextError};
pub use versioning::McpContractChange;
