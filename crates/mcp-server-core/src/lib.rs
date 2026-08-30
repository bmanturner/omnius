//! Stateless MCP dispatch over the canonical application capability registry.
//!
//! Application and composition code use only the SDK-free contracts exported from
//! this module. Omnius-owned transports terminate RMCP values in the hidden [`sdk`]
//! boundary before constructing canonical registry invocations.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod kernel;
mod metadata;

#[doc(hidden)]
pub mod sdk;

pub use kernel::{
    MCP_PROTOCOL_REVISION, McpDispatch, McpDispatchError, McpDispatchErrorCode, McpDispatchFuture,
    McpDispatchRequest, McpKernel, McpPrimitive,
};
pub use metadata::{
    MAX_CLIENT_CAPABILITIES, MAX_CLIENT_NAME_BYTES, MAX_CLIENT_VERSION_BYTES,
    MAX_METADATA_IDENTIFIER_BYTES, MAX_NEGOTIATED_EXTENSIONS, McpClientIdentity, McpLogLevel,
    McpMetadataError, McpRequestMetadata,
};
