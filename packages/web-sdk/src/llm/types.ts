/**
 * Provider-neutral LLM wire contracts owned by the hand-written SDK.
 *
 * These mirror the canonical Rust serde models and intentionally remain
 * independent of the generated HTTP client, whose schemas cover mounted routes only.
 */

export type StructuredValidation = "valid" | "invalid" | "not-requested";
export type TextFormat = "plain" | "markdown" | "html-fragment";
export type ToolResultStatus = "success" | "error" | "cancelled";

export type BinarySource =
  | { data_base64: string; type: "inline" }
  | { type: "url"; url: string }
  | { object_key: string; type: "object" };

export type UtcTimestamp = string;

export type AnnotationType =
  | "citation"
  | "grounding"
  | "url"
  | "file-path"
  | "token-score"
  | "log-probability"
  | "safety"
  | "moderation"
  | "provider";

export type ExecutionOperation =
  | "web-search"
  | "file-search"
  | "code-execution"
  | "shell"
  | "computer-use"
  | "image-generation"
  | "audio-generation"
  | "video-generation"
  | "mcp"
  | "provider-tool"
  | "other";

export type ExecutionStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type SafetyDisposition = "allowed" | "filtered" | "blocked" | "refused" | "review-required";
export type ReasoningRepresentation = "summary" | "signature" | "opaque-encrypted";

/** One ordered canonical output part. */
export type LlmOutputPart =
  | {
      annotations?: { [key: string]: unknown };
      format?: TextFormat;
      id: string;
      kind: "text";
      provider_metadata?: { [key: string]: unknown };
      text: string;
    }
  | {
      annotations?: { [key: string]: unknown };
      id: string;
      kind: "structured";
      provider_metadata?: { [key: string]: unknown };
      repair_attempts?: number;
      schema_id?: string | null;
      validation: StructuredValidation;
      value: unknown;
    }
  | {
      annotations?: { [key: string]: unknown };
      arguments: unknown;
      call_id: string;
      capability_id?: string | null;
      id: string;
      kind: "tool_call";
      name: string;
      provider_metadata?: { [key: string]: unknown };
    }
  | {
      annotations?: { [key: string]: unknown };
      call_id: string;
      content: LlmOutputPart[];
      id: string;
      kind: "tool_result";
      provider_metadata?: { [key: string]: unknown };
      status: ToolResultStatus;
    }
  | {
      annotations?: { [key: string]: unknown };
      end?: number | null;
      id: string;
      kind: "citation";
      part_id?: string | null;
      provider_metadata?: { [key: string]: unknown };
      source: { [key: string]: unknown };
      start?: number | null;
    }
  | {
      annotations?: { [key: string]: unknown };
      category: string;
      id: string;
      kind: "refusal";
      message: string;
      provider_metadata?: { [key: string]: unknown };
      retryable?: boolean;
    }
  | {
      annotations?: { [key: string]: unknown };
      generation_id?: string | null;
      height?: number | null;
      id: string;
      kind: "image";
      mime_type: string;
      provider_metadata?: { [key: string]: unknown };
      source: BinarySource;
      width?: number | null;
    }
  | {
      annotations?: { [key: string]: unknown };
      duration_ms?: number | null;
      id: string;
      kind: "audio";
      mime_type: string;
      provider_metadata?: { [key: string]: unknown };
      sample_rate_hz?: number | null;
      source: BinarySource;
      transcript?: string | null;
    }
  | {
      annotations?: { [key: string]: unknown };
      duration_ms?: number | null;
      frame_rate: number | null;
      height?: number | null;
      id: string;
      kind: "video";
      mime_type: string;
      provider_metadata?: { [key: string]: unknown };
      source: BinarySource;
      width?: number | null;
    }
  | {
      annotations?: { [key: string]: unknown };
      filename?: string | null;
      id: string;
      kind: "file";
      mime_type: string;
      provider_metadata?: { [key: string]: unknown };
      sha256: string | null;
      size_bytes?: number | null;
      source: BinarySource;
    }
  | {
      annotations?: { [key: string]: unknown };
      expires_at?: UtcTimestamp | null;
      id: string;
      kind: "resource";
      mime_type?: string | null;
      name?: string | null;
      provider_metadata?: { [key: string]: unknown };
      resource_metadata?: { [key: string]: unknown };
      source?: BinarySource | null;
      uri: string;
    }
  | {
      annotation_type: AnnotationType;
      annotations?: { [key: string]: unknown };
      data: unknown;
      end?: number | null;
      id: string;
      kind: "annotation";
      part_id?: string | null;
      provider_metadata?: { [key: string]: unknown };
      start?: number | null;
    }
  | {
      annotations?: { [key: string]: unknown };
      completed_at?: UtcTimestamp | null;
      error?: { [key: string]: unknown } | null;
      id: string;
      input?: unknown;
      kind: "execution_step";
      operation: ExecutionOperation;
      output?: unknown;
      provider_metadata?: { [key: string]: unknown };
      started_at?: UtcTimestamp | null;
      status: ExecutionStatus;
      step_id: string;
    }
  | {
      annotations?: { [key: string]: unknown };
      category?: string | null;
      disposition: SafetyDisposition;
      id: string;
      kind: "safety";
      message?: string | null;
      policy_id?: string | null;
      provider_metadata?: { [key: string]: unknown };
      scores?: { [key: string]: unknown };
    }
  | {
      annotations?: { [key: string]: unknown };
      data: string;
      id: string;
      kind: "reasoning";
      provider_metadata?: { [key: string]: unknown };
      representation: ReasoningRepresentation;
    }
  | {
      annotations?: { [key: string]: unknown };
      id: string;
      kind: "unknown";
      payload: unknown;
      provider_kind: string;
      provider_metadata?: { [key: string]: unknown };
    };

export interface ToolCallOutputPart {
  annotations?: { [key: string]: unknown };
  arguments: unknown;
  call_id: string;
  capability_id?: string | null;
  id: string;
  name: string;
  provider_metadata?: { [key: string]: unknown };
}

export interface ToolResultOutputPart {
  annotations?: { [key: string]: unknown };
  call_id: string;
  content: LlmOutputPart[];
  id: string;
  provider_metadata?: { [key: string]: unknown };
  status: ToolResultStatus;
}

export interface ImageOutputPart {
  annotations?: { [key: string]: unknown };
  generation_id?: string | null;
  height?: number | null;
  id: string;
  mime_type: string;
  provider_metadata?: { [key: string]: unknown };
  source: BinarySource;
  width?: number | null;
}

export interface AudioOutputPart {
  annotations?: { [key: string]: unknown };
  duration_ms?: number | null;
  id: string;
  mime_type: string;
  provider_metadata?: { [key: string]: unknown };
  sample_rate_hz?: number | null;
  source: BinarySource;
  transcript?: string | null;
}

export interface VideoOutputPart {
  annotations?: { [key: string]: unknown };
  duration_ms?: number | null;
  frame_rate: number | null;
  height?: number | null;
  id: string;
  mime_type: string;
  provider_metadata?: { [key: string]: unknown };
  source: BinarySource;
  width?: number | null;
}

export interface FileOutputPart {
  annotations?: { [key: string]: unknown };
  filename?: string | null;
  id: string;
  mime_type: string;
  provider_metadata?: { [key: string]: unknown };
  sha256: string | null;
  size_bytes?: number | null;
  source: BinarySource;
}

export interface CitationOutputPart {
  annotations?: { [key: string]: unknown };
  end?: number | null;
  id: string;
  part_id?: string | null;
  provider_metadata?: { [key: string]: unknown };
  source: { [key: string]: unknown };
  start?: number | null;
}

export interface StructuredOutputPart {
  annotations?: { [key: string]: unknown };
  id: string;
  provider_metadata?: { [key: string]: unknown };
  repair_attempts?: number;
  schema_id?: string | null;
  validation: StructuredValidation;
  value: unknown;
}

export interface ReasoningOutputPart {
  annotations?: { [key: string]: unknown };
  data: string;
  id: string;
  provider_metadata?: { [key: string]: unknown };
  representation: ReasoningRepresentation;
}

/** A canonical media payload retained without provider-specific wrappers. */
export type StreamMedia =
  | { media_type: "image"; part: ImageOutputPart }
  | { media_type: "audio"; part: AudioOutputPart }
  | { media_type: "video"; part: VideoOutputPart }
  | { media_type: "file"; part: FileOutputPart };

export type AcceptedPublicContent =
  | { content: { part_id: string; text: string }; content_type: "text" }
  | { content: StructuredOutputPart; content_type: "structured" }
  | {
      content: { correlation_id: string; part: ToolCallOutputPart };
      content_type: "tool_call";
    }
  | { content: ToolResultOutputPart; content_type: "tool_result" }
  | { content: ReasoningOutputPart; content_type: "safe_reasoning" }
  | { content: StreamMedia; content_type: "media" }
  | { content: CitationOutputPart; content_type: "citation" };

export interface AiRoute {
  model: string;
  provider: string;
  ready: boolean;
  route: string;
}

export type CompletionStatus = "completed" | "partial" | "refused" | "cancelled" | "failed";

export interface Candidate {
  id?: string | null;
  index: number;
  output: LlmOutputPart[];
  provider_metadata?: { [key: string]: unknown };
  status: CompletionStatus;
  stop_reason?: string | null;
}

/** One ordered, heterogeneous message input part. */
export type LlmInputPart =
  | { kind: "text"; text: string }
  | { kind: "structured"; value: unknown }
  | { kind: "image"; mime_type: string; source: BinarySource }
  | { kind: "audio"; mime_type: string; source: BinarySource }
  | { kind: "video"; mime_type: string; source: BinarySource }
  | { filename?: string | null; kind: "file"; mime_type: string; source: BinarySource }
  | { kind: "resource"; mime_type?: string | null; uri: string }
  | { call_id: string; content: unknown[]; kind: "tool_result"; status: ToolResultStatus };

export type MessageRole = "system" | "developer" | "user" | "assistant" | "tool";

export interface LlmMessage {
  content: LlmInputPart[];
  id?: string | null;
  metadata?: { [key: string]: unknown };
  name?: string | null;
  role: MessageRole;
}

export type DurableJobStatus = "pending" | "running" | "succeeded" | "failed" | "cancelled";

export interface GenerationConfig {
  candidate_count?: number | null;
  max_output_tokens?: number | null;
  seed?: number | null;
  stop?: string[];
  temperature?: number | null;
  top_p?: number | null;
}

export interface LlmJob {
  job_id: string;
  status: DurableJobStatus;
}

export interface LlmJobSubmission {
  job_id: string;
  status: DurableJobStatus;
}

export interface RequestLimits {
  deadline_ms: number;
  max_cost_microunits?: number | null;
  max_input_bytes?: number | null;
  max_model_turns: number;
  max_output_bytes?: number | null;
  max_tool_calls: number;
}

export type OutputMode = "auto" | "text" | "structured" | "tools" | "media";
export type SchemaDefinition = { [key: string]: unknown } | boolean;

export interface OutputRequest {
  mime_types?: string[];
  mode: OutputMode;
  schema?: SchemaDefinition | null;
  schema_id?: string | null;
  strict?: boolean;
}

export type LlmRequestId = string;

export interface Route {
  id: string;
  preferred_capabilities?: string[];
  required_capabilities?: string[];
  revision?: number | null;
}

export type SchemaVersion = "1.0.0";

export interface ToolDefinition {
  capability_id?: string | null;
  description?: string | null;
  input_schema: SchemaDefinition;
  name: string;
  output_schema?: SchemaDefinition | null;
}

/** The complete provider-neutral canonical LLM request. */
export interface LlmRequest {
  data_policy?: { [key: string]: unknown };
  generation?: GenerationConfig;
  limits: RequestLimits;
  messages: LlmMessage[];
  metadata?: { [key: string]: unknown };
  output: OutputRequest;
  principal_context?: { [key: string]: unknown };
  request_id: LlmRequestId;
  route: Route;
  schema_version: SchemaVersion;
  tenant_context?: { [key: string]: unknown };
  tool_policy?: { [key: string]: unknown };
  tools?: ToolDefinition[];
}

export interface Usage {
  actual_cost_microunits?: number | null;
  audio_input_tokens?: number | null;
  audio_output_tokens?: number | null;
  cache_read_tokens?: number | null;
  cache_write_tokens?: number | null;
  cached_input_tokens?: number | null;
  estimated_cost_microunits?: number | null;
  image_input_units?: number | null;
  image_output_units?: number | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  provider_units?: { [key: string]: unknown };
  reasoning_tokens?: number | null;
  tool_execution_units?: number | null;
  video_input_units?: number | null;
  video_output_units?: number | null;
}

/** A complete canonical completion response. */
export interface LlmResponse {
  candidates?: Candidate[];
  created_at: UtcTimestamp;
  model: string;
  output: LlmOutputPart[];
  provider: string;
  provider_metadata?: { [key: string]: unknown };
  provider_request_id?: string | null;
  provider_response_id?: string | null;
  request_id: LlmRequestId;
  response_id: string;
  schema_version: SchemaVersion;
  selected_candidate_index?: number | null;
  status: CompletionStatus;
  stop_reason?: string | null;
  usage: Usage;
  warnings?: string[];
}

export interface LlmRouteList {
  routes: AiRoute[];
}

export type StreamPartKind =
  | "text"
  | "structured"
  | "tool_call"
  | "tool_result"
  | "safe_reasoning"
  | "media"
  | "citation";

export type StreamToolCallDelta =
  | { field: "name"; value: string }
  | { field: "arguments_fragment"; value: string };

export type StreamWarningCode =
  | "provider_extension_omitted"
  | "private_reasoning_omitted"
  | "text_coalesced"
  | "estimated_usage";

/** Non-terminal canonical stream data. */
export type LlmStreamEventData =
  | { data: { response_id: string }; event: "response_start" }
  | { data: { kind: StreamPartKind; part_id: string }; event: "part_start" }
  | { data: { part_id: string; text: string }; event: "text_delta" }
  | { data: StructuredOutputPart; event: "structured_complete" }
  | {
      data: { correlation_id: string; delta: StreamToolCallDelta; part_id: string };
      event: "tool_call_delta";
    }
  | {
      data: { correlation_id: string; part: ToolCallOutputPart };
      event: "tool_call_complete";
    }
  | { data: ToolResultOutputPart; event: "tool_result_complete" }
  | { data: ReasoningOutputPart; event: "safe_reasoning" }
  | { data: StreamMedia; event: "media" }
  | { data: CitationOutputPart; event: "citation" }
  | { data: Usage; event: "usage" }
  | { data: StreamWarningCode; event: "warning" }
  | { data: { part_id: string }; event: "part_complete" };

export type StreamBudgetDimension =
  | "model_turns"
  | "tool_calls"
  | "wall_clock"
  | "tokens"
  | "cost"
  | "concurrency";
export type StreamFailureKind = "protocol" | "transport" | "internal";
export type StreamInterruption = "transport" | "protocol" | "consumer_disconnected" | "deadline";

/** Exactly one explicit terminal state for a canonical stream. */
export type StreamTerminalState =
  | { state: "completed" }
  | { state: "provider_refused" }
  | { state: "safety_refused" }
  | { state: "invalid_structured_data" }
  | { state: "tool_execution_failed" }
  | { detail: StreamBudgetDimension; state: "budget_exhausted" }
  | { state: "cancelled" }
  | { detail: StreamFailureKind; state: "failed" }
  | { detail: StreamInterruption; state: "partial_interrupted" };

export interface StreamTerminal {
  accepted_public_content: AcceptedPublicContent[];
  state: StreamTerminalState;
}

export type LlmStreamPayload =
  | { data: LlmStreamEventData; event: "event" }
  | { data: StreamTerminal; event: "terminal" };

/** One versioned, request-correlated, strictly sequenced canonical stream event. */
export interface LlmStreamEvent {
  payload: LlmStreamPayload;
  request_id: LlmRequestId;
  schema_version: SchemaVersion;
  sequence: number;
}
