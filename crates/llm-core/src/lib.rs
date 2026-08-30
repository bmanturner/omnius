//! Provider-neutral request and completion response contracts for LLM adapters.
//!
//! The crate owns the stable JSON boundary used by application services. Provider
//! adapters translate their SDK values into these ordered, versioned contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod request;
mod response;
mod value;

pub use request::{
    AudioInputPart, BinarySource, FileInputPart, GenerationConfig, ImageInputPart,
    InlineBinarySource, LlmInputPart, LlmMessage, LlmRequest, MessageRole, ObjectBinarySource,
    OutputMode, OutputRequest, RequestLimits, ResourceInputPart, Route, SchemaDefinition,
    StructuredInputPart, TextInputPart, ToolDefinition, ToolResultInputPart, ToolResultStatus,
    UrlBinarySource, VideoInputPart,
};
pub use response::{
    Candidate, CompletionStatus, LlmOutputPart, LlmResponse, StructuredOutputPart,
    StructuredValidation, TextFormat, TextOutputPart, ToolCallOutputPart, ToolResultOutputPart,
    Usage,
};
pub use value::{ContractError, JsonObject, LlmRequestId, SchemaVersion, UtcTimestamp};
