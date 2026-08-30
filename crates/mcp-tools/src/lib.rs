//! Canonical, transport-neutral MCP tool projection over the shared capability registry.
//!
//! The crate compiles bounded local-only JSON Schema Draft 2020-12 documents, publishes immutable
//! authorization-filtered catalogs, invokes tools only through [`McpKernel`], and maps validated
//! output into an RMCP-independent result algebra. It owns no session, transport, RMCP handler, or
//! alternate executable handler registry.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adapter;
mod catalog;
mod projection;
mod result;
mod schema;
mod value;

pub use adapter::{CurrentResultAdapter, ResultAdapterError};
pub use catalog::{
    CacheControlError, CatalogCacheControl, CatalogCacheScope, CatalogEtag, CatalogMeta,
    CatalogMetadataError, CompatibilityState, MAX_CATALOG_TTL_MS, MAX_REQUIRED_EXTENSIONS,
    ToolCatalog, ToolCatalogError, ToolDeclaration, ToolDeclarationError, ToolDescriptor, ToolList,
};
pub use omnius_mcp_server_core::{McpExtension, McpExtensionId, McpExtensionRevision, McpKernel};
pub use projection::{
    ToolAuthorizationDecision, ToolAuthorizationOperation, ToolAuthorizationRequest,
    ToolAuthorizer, ToolCallRequest, ToolProjection, ToolProtocolError,
};
pub use result::{
    BinaryContent, BoundedContent, CanonicalToolResult, CompleteToolResult, ContentBlock,
    EmbeddedBinaryContent, EmbeddedResource, EmbeddedResourceContents, EmbeddedResourceUri,
    InputPrompt, InputRequest, InputRequestId, InputRequiredToolResult, MAX_BINARY_CONTENT_BYTES,
    MAX_CONTENT_BLOCKS, MAX_INPUT_PROMPT_BYTES, MAX_INPUT_REQUEST_ID_BYTES, MAX_INPUT_REQUESTS,
    MAX_MEDIA_TYPE_BYTES, MAX_REQUEST_STATE_BYTES, MAX_RESOURCE_URI_BYTES, MAX_TEXT_CONTENT_BYTES,
    MediaType, RequestState, ResultBuildError, TextContent, ToolFailure, ToolFailureCode,
    ToolOutcome, ToolRepresentation, ToolResultAdapter,
};
pub use schema::{JsonSchemaDocument, SchemaDocumentError, SchemaValidationError};
pub use value::{
    CatalogRevision, MAX_REVISION_BYTES, MAX_TOOL_DESCRIPTION_BYTES, MAX_TOOL_NAME_BYTES,
    MAX_TOOL_TITLE_BYTES, PublicValueError, SchemaRevision, ToolDescription, ToolName, ToolTitle,
};
