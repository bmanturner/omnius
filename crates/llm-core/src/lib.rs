//! Provider-neutral request, content, and model-operation contracts for LLM adapters.
//!
//! The crate owns the stable JSON boundary used by application services. Provider
//! adapters translate their SDK values into these ordered, versioned contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod extended_content;
mod model_response;
/// Provider-neutral LLM execution, streaming, raw-retention, and error contracts.
pub mod provider;
mod request;
mod response;
mod value;

pub use extended_content::{
    AnnotationOutputPart, AnnotationType, AudioOutputPart, CitationOutputPart, ContentLimits,
    ExecutionOperation, ExecutionStatus, ExecutionStepOutputPart, FileOutputPart, ImageOutputPart,
    ReasoningOutputPart, ReasoningRepresentation, RefusalOutputPart, ResourceOutputPart,
    SafetyDisposition, SafetyOutputPart, UnknownOutputPart, VideoOutputPart,
};
pub use model_response::{
    BinaryEmbedding, BinaryEmbeddingEncoding, ClassificationLabel, ClassificationResponse,
    ClassificationResult, DenseEmbedding, EmbeddingItem, EmbeddingResponse, EmbeddingValue,
    EmbeddingVector, GeneratedAsset, GeneratedAssetKind, GenerationSeed, MediaGenerationResponse,
    ModelOperation, ModelResponse, ModelUsage, MultiVectorEmbedding, RerankResponse, RerankResult,
    SparseEmbedding, SpeechAudio, SpeechResponse, SpeechTimingKind, SpeechTimingMark,
    TranscriptSegment, TranscriptWord, TranscriptionResponse,
};
pub use provider::{
    LlmProvider, ProviderCompletionDiagnostics, ProviderCompletionResult, ProviderError,
    ProviderErrorKind, ProviderStream, ProviderStreamEvent, ProviderToolCallDelta, RawPayloadKind,
    RawRetentionPolicy, RawRetentionState, RawSummary, RetainedRaw, RetryClass, UnsupportedFeature,
};
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
