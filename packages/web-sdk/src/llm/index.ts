import type {
  LlmJob,
  LlmJobSubmission,
  LlmOutputPart,
  LlmRequest,
  LlmResponse,
  LlmRouteList,
  LlmStreamEvent,
  StreamMedia,
} from "../internal/generated/http/core.js";
import { IDEMPOTENCY_KEY_HEADER, parseIdempotencyKey } from "../client/idempotency.js";
import type {
  ServiceClient,
  ServiceRequestOptions,
  ServiceResponse,
} from "../client/transport.js";
import {
  streamLlmResponse,
  type LlmStreamOptions,
  type ValidatedLlmStreamItem,
} from "./stream.js";

type AudioOutputPart = Extract<LlmOutputPart, { kind: "audio" }>;
type CitationOutputPart = Extract<LlmOutputPart, { kind: "citation" }>;
type FileOutputPart = Extract<LlmOutputPart, { kind: "file" }>;
type ImageOutputPart = Extract<LlmOutputPart, { kind: "image" }>;
type ToolCallOutputPart = Extract<LlmOutputPart, { kind: "tool_call" }>;
type ToolResultOutputPart = Extract<LlmOutputPart, { kind: "tool_result" }>;
type VideoOutputPart = Extract<LlmOutputPart, { kind: "video" }>;

export const AI_OPERATION_IDS = Object.freeze({
  routesList: "aiRoutesList",
  responseCreate: "aiResponseCreate",
  responseStream: "aiResponseStream",
  jobSubmit: "aiJobSubmit",
  jobGet: "aiJobGet",
  jobCancel: "aiJobCancel",
  jobResult: "aiJobResult",
} as const);

const AI_ROUTES_PATH = "/api/ai/routes";
const AI_RESPONSES_PATH = "/api/ai/responses";
const AI_JOBS_PATH = "/api/ai/jobs";

export interface LlmRequestOptions extends ServiceRequestOptions {
  /** Explicit tenant context for deployments using tenant headers. */
  readonly tenantId?: string;
  /** Retry-stable key used for generation and durable submission. */
  readonly idempotencyKey?: string;
}

export interface LlmClient {
  /** Lists product-approved routes without exposing unrestricted provider model identifiers. */
  listRoutes(options?: LlmRequestOptions): Promise<ServiceResponse<LlmRouteList>>;
  /** Creates one synchronous canonical response. */
  createResponse(
    request: LlmRequest,
    options?: LlmRequestOptions,
  ): Promise<ServiceResponse<LlmResponse>>;
  /** Opens one strictly sequenced canonical SSE response. */
  streamResponse(
    request: LlmRequest,
    options?: LlmStreamOptions,
  ): AsyncGenerator<ValidatedLlmStreamItem, void, undefined>;
  /** Submits the same canonical request for durable execution. */
  submitJob(
    request: LlmRequest,
    options?: LlmRequestOptions,
  ): Promise<ServiceResponse<LlmJobSubmission>>;
  /** Loads durable job status. */
  getJob(jobId: string, options?: LlmRequestOptions): Promise<ServiceResponse<LlmJob>>;
  /** Cooperatively cancels a durable job. */
  cancelJob(
    jobId: string,
    options?: LlmRequestOptions,
  ): Promise<ServiceResponse<void>>;
  /** Loads the original canonical response unchanged after durable completion. */
  getJobResult(
    jobId: string,
    options?: LlmRequestOptions,
  ): Promise<ServiceResponse<LlmResponse>>;
}

/** Creates the framework-neutral LLM API over the established authenticated service client. */
export function createLlmClient(client: ServiceClient): LlmClient {
  return Object.freeze({
    listRoutes(options = {}) {
      return client.request<LlmRouteList>(AI_ROUTES_PATH, requestOptions("GET", undefined, options));
    },
    createResponse(request: LlmRequest, options: LlmRequestOptions = {}) {
      return client.request<LlmResponse>(
        AI_RESPONSES_PATH,
        requestOptions("POST", request, options),
      );
    },
    streamResponse(request: LlmRequest, options: LlmStreamOptions = {}) {
      return streamLlmResponse(client, request, options);
    },
    submitJob(request: LlmRequest, options: LlmRequestOptions = {}) {
      return client.request<LlmJobSubmission>(
        AI_JOBS_PATH,
        requestOptions("POST", request, options),
      );
    },
    getJob(jobId: string, options: LlmRequestOptions = {}) {
      return client.request<LlmJob>(jobPath(jobId), requestOptions("GET", undefined, options));
    },
    cancelJob(jobId: string, options: LlmRequestOptions = {}) {
      return client.request<void>(
        jobPath(jobId),
        requestOptions("DELETE", undefined, options),
      );
    },
    getJobResult(jobId: string, options: LlmRequestOptions = {}) {
      return client.request<LlmResponse>(
        `${jobPath(jobId)}/result`,
        requestOptions("GET", undefined, options),
      );
    },
  });
}

export type ToolApprovalDecision = "pending" | "approved" | "denied" | "expired";

/** Local approval state that retains the canonical tool call unchanged. */
export interface ToolApprovalState {
  readonly call: ToolCallOutputPart;
  readonly decision: ToolApprovalDecision;
}

/** Starts a client-owned approval decision without making incomplete stream deltas executable. */
export function createToolApprovalState(call: ToolCallOutputPart): ToolApprovalState {
  return Object.freeze({ call, decision: "pending" });
}

/** Applies one terminal human decision exactly once. */
export function decideToolApproval(
  state: ToolApprovalState,
  decision: Exclude<ToolApprovalDecision, "pending">,
): ToolApprovalState {
  if (state.decision !== "pending") {
    throw new TypeError("A tool approval decision is already terminal.");
  }
  return Object.freeze({ call: state.call, decision });
}

export type LlmOutputClassification =
  | "text"
  | "structured"
  | "tool_call"
  | "tool_result"
  | "reasoning"
  | "citation"
  | "refusal"
  | "image"
  | "audio"
  | "video"
  | "file"
  | "unknown";

/** Classifies only the canonical discriminant; unknown future parts remain inert data. */
export function classifyLlmOutputPart(value: unknown): LlmOutputClassification {
  if (typeof value !== "object" || value === null || !("kind" in value)) {
    return "unknown";
  }
  const kind = value.kind;
  return kind === "text" ||
    kind === "structured" ||
    kind === "tool_call" ||
    kind === "tool_result" ||
    kind === "reasoning" ||
    kind === "citation" ||
    kind === "refusal" ||
    kind === "image" ||
    kind === "audio" ||
    kind === "video" ||
    kind === "file"
    ? kind
    : "unknown";
}

/** Extracts canonical citations without interpreting or rendering their untrusted source data. */
export function citationsFromResponse(response: LlmResponse): readonly CitationOutputPart[] {
  return response.output.filter(isCitationOutputPart);
}

/** Narrows one canonical citation without interpreting source text, HTML, or markdown. */
export function isCitationOutputPart(part: LlmOutputPart): part is CitationOutputPart {
  return classifyLlmOutputPart(part) === "citation";
}

/** Narrows one complete canonical tool call; stream deltas never satisfy this guard. */
export function isToolCallOutputPart(part: LlmOutputPart): part is ToolCallOutputPart {
  return classifyLlmOutputPart(part) === "tool_call";
}

/** Narrows one complete canonical tool result. */
export function isToolResultOutputPart(part: LlmOutputPart): part is ToolResultOutputPart {
  return classifyLlmOutputPart(part) === "tool_result";
}

export type LlmMediaOutputPart =
  | ImageOutputPart
  | AudioOutputPart
  | VideoOutputPart
  | FileOutputPart;

/** Extracts canonical media parts while preserving opaque object references. */
export function mediaFromResponse(response: LlmResponse): readonly LlmMediaOutputPart[] {
  return response.output.filter(isMediaOutputPart);
}

/** Narrows canonical media output while leaving every asset reference opaque. */
export function isMediaOutputPart(part: LlmOutputPart): part is LlmMediaOutputPart {
  const kind = classifyLlmOutputPart(part);
  return kind === "image" || kind === "audio" || kind === "video" || kind === "file";
}

function requestOptions(
  method: "GET" | "POST" | "DELETE",
  body: LlmRequest | undefined,
  options: LlmRequestOptions,
): ServiceRequestOptions {
  const headers = new Headers(options.headers);
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (options.idempotencyKey !== undefined) {
    headers.set(IDEMPOTENCY_KEY_HEADER, parseIdempotencyKey(options.idempotencyKey));
  }
  if (options.tenantId !== undefined) {
    validateUuidV7(options.tenantId, "tenantId");
    headers.set("X-Omnius-Tenant-Id", options.tenantId);
  }
  const {
    tenantId: _tenantId,
    idempotencyKey: _idempotencyKey,
    headers: _headers,
    body: _body,
    method: _method,
    ...request
  } = options;
  void _tenantId;
  void _idempotencyKey;
  void _headers;
  void _body;
  void _method;
  return {
    ...request,
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

function jobPath(jobId: string): string {
  validateUuidV7(jobId, "jobId");
  return `${AI_JOBS_PATH}/${jobId}`;
}

function validateUuidV7(value: string, name: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)) {
    throw new TypeError(`${name} must be a canonical UUIDv7.`);
  }
}

export { LlmStreamHttpError, LlmStreamProtocolError, parseLlmEventStream } from "./stream.js";
export type {
  LlmStreamOptions,
  LlmStreamTerminalOutcome,
  ValidatedLlmStreamItem,
} from "./stream.js";

export type {
  AudioOutputPart,
  CitationOutputPart,
  FileOutputPart,
  ImageOutputPart,
  LlmJob,
  LlmJobSubmission,
  LlmOutputPart,
  LlmRequest,
  LlmResponse,
  LlmRouteList,
  LlmStreamEvent,
  StreamMedia,
  ToolCallOutputPart,
  ToolResultOutputPart,
  VideoOutputPart,
};
