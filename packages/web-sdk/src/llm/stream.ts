import {
  AbortedRequestError,
  ContractMismatchError,
  GENERATED_AGAINST_CONTRACT_HASH,
  InvalidResponseError,
  NetworkRequestError,
  RUNTIME_CONTRACT_HASH_HEADER,
  RUNTIME_MAXIMUM_SDK_HEADER,
  RUNTIME_MINIMUM_SDK_HEADER,
  ServiceClientError,
  parseRetryAfter,
  type ClientRequestContext,
  type ServiceClient,
  type ServiceRequestOptions,
} from "../client/index.js";
import { isUnknownRecord } from "../client/type-guards.js";
import { IDEMPOTENCY_KEY_HEADER, parseIdempotencyKey } from "../client/idempotency.js";
import {
  retryDelayMs,
  shouldRetryRequest,
  validateRetryPolicy,
  type RetryPolicy,
} from "../client/retry.js";
import type { LlmRequest, LlmStreamEvent } from "./types.js";

const STREAM_PATH = "/api/ai/responses/stream";
const DEFAULT_MAX_EVENT_BYTES = 1024 * 1024;
const CANONICAL_SCHEMA_VERSION = "1.0.0";
const DEFAULT_MAX_EVENTS = 65_536;
const TERMINAL_STATES: Readonly<Record<LlmStreamTerminalOutcome, true>> = Object.freeze({
  completed: true,
  provider_refused: true,
  safety_refused: true,
  invalid_structured_data: true,
  tool_execution_failed: true,
  budget_exhausted: true,
  cancelled: true,
  failed: true,
  partial_interrupted: true,
});
const RETRYABLE_STATUSES: Readonly<Record<number, true>> = Object.freeze({
  408: true,
  425: true,
  429: true,
  502: true,
  503: true,
  504: true,
});
const UTF8_ENCODER = new TextEncoder();

export type LlmStreamTerminalOutcome =
  | "completed"
  | "provider_refused"
  | "safety_refused"
  | "invalid_structured_data"
  | "tool_execution_failed"
  | "budget_exhausted"
  | "cancelled"
  | "failed"
  | "partial_interrupted";

/** A canonical event plus transport validation state; the canonical event is never reshaped. */
export type ValidatedLlmStreamItem =
  | { readonly kind: "event"; readonly event: LlmStreamEvent }
  | {
      readonly kind: "terminal";
      readonly outcome: LlmStreamTerminalOutcome;
      readonly event: LlmStreamEvent;
    };

export interface LlmStreamOptions extends ServiceRequestOptions {
  /** Retry-stable key required before POST retries are eligible. */
  readonly idempotencyKey?: string;
  /** Explicit tenant context for deployments using tenant headers. */
  readonly tenantId?: string;
  /** Maximum serialized JSON bytes accepted for one SSE event. */
  readonly maxEventBytes?: number;
  /** Maximum canonical events including the terminal event. */
  readonly maxEvents?: number;
}

export class LlmStreamProtocolError extends Error {
  override readonly name = "LlmStreamProtocolError";

  constructor(message = "The LLM stream violated the canonical event protocol.") {
    super(message);
  }
}

export class LlmStreamHttpError extends ServiceClientError {
  override readonly name = "LlmStreamHttpError";
  readonly status: number;

  constructor(status: number, requestId: string | undefined) {
    const retryable = RETRYABLE_STATUSES[status] === true;
    super(
      `The LLM stream request failed (HTTP ${String(status)}).`,
      "problem",
      retryable,
      requestId,
    );
    this.status = status;
  }
}

/** Opens and validates canonical SSE without buffering generated content. */
export async function* streamLlmResponse(
  client: ServiceClient,
  request: LlmRequest,
  options: LlmStreamOptions = {},
): AsyncGenerator<ValidatedLlmStreamItem, void, undefined> {
  const maxEventBytes = positiveBound(options.maxEventBytes ?? DEFAULT_MAX_EVENT_BYTES, "maxEventBytes");
  const maxEvents = positiveBound(options.maxEvents ?? DEFAULT_MAX_EVENTS, "maxEvents");
  const composed = composeSignal(options.signal, options.deadlineMs);
  try {
    const response = await openEventStream(client, request, options, composed);
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    const requestId = responseRequestId(response.headers);
    if (contentType !== "text/event-stream" || response.body === null) {
      throw new InvalidResponseError(
        response.status,
        "The LLM stream response was not a readable text/event-stream.",
        requestId,
      );
    }
    yield* parseLlmEventStream(response.body, { maxEventBytes, maxEvents });
  } finally {
    composed.cleanup();
  }
}

/** Validates a canonical SSE body supplied by tests, service workers, or alternate transports. */
export async function* parseLlmEventStream(
  body: ReadableStream<Uint8Array>,
  options: { readonly maxEventBytes?: number; readonly maxEvents?: number } = {},
): AsyncGenerator<ValidatedLlmStreamItem, void, undefined> {
  const maxEventBytes = positiveBound(options.maxEventBytes ?? DEFAULT_MAX_EVENT_BYTES, "maxEventBytes");
  const maxEvents = positiveBound(options.maxEvents ?? DEFAULT_MAX_EVENTS, "maxEvents");
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let dataLines: string[] = [];
  let eventName: string | undefined;
  let expectedSequence = 0;
  let requestId: string | undefined;
  let schemaVersion: string | undefined;
  let terminal = false;
  let eventCount = 0;

  const dispatch = (): ValidatedLlmStreamItem | undefined => {
    if (dataLines.length === 0) {
      eventName = undefined;
      return undefined;
    }
    if (eventName !== undefined && eventName !== "message" && eventName !== "llm") {
      throw new LlmStreamProtocolError();
    }
    const data = dataLines.join("\n");
    dataLines = [];
    eventName = undefined;
    if (UTF8_ENCODER.encode(data).byteLength > maxEventBytes) {
      throw new LlmStreamProtocolError("An LLM stream event exceeded the configured byte limit.");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(data) as unknown;
    } catch {
      throw new LlmStreamProtocolError();
    }
    const validated = validateCanonicalEvent(decoded);
    if (terminal || validated.sequence !== expectedSequence) {
      throw new LlmStreamProtocolError();
    }
    if (requestId === undefined) {
      requestId = validated.requestId;
      schemaVersion = validated.schemaVersion;
    } else if (requestId !== validated.requestId || schemaVersion !== validated.schemaVersion) {
      throw new LlmStreamProtocolError();
    }
    expectedSequence += 1;
    eventCount += 1;
    if (eventCount > maxEvents) {
      throw new LlmStreamProtocolError("The LLM stream exceeded the configured event limit.");
    }
    if (validated.outcome === undefined) {
      return { kind: "event", event: decoded as LlmStreamEvent };
    }
    terminal = true;
    return {
      kind: "terminal",
      outcome: validated.outcome,
      event: decoded as LlmStreamEvent,
    };
  };

  const acceptLine = (line: string): ValidatedLlmStreamItem | undefined => {
    if (line.length === 0) {
      return dispatch();
    }
    if (line.startsWith(":")) {
      return undefined;
    }
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    if (field === "data") {
      dataLines.push(value);
    } else if (field === "event") {
      if (eventName !== undefined) {
        throw new LlmStreamProtocolError();
      }
      eventName = value;
    } else {
      throw new LlmStreamProtocolError();
    }
    return undefined;
  };

  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) {
        buffer += decoder.decode();
        break;
      }
      buffer += decoder.decode(chunk.value, { stream: true });
      if (UTF8_ENCODER.encode(buffer).byteLength > maxEventBytes + 16 * 1024) {
        throw new LlmStreamProtocolError("An LLM stream frame exceeded the configured byte limit.");
      }
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) {
          break;
        }
        const rawLine = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        const item = acceptLine(rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine);
        if (item !== undefined) {
          yield item;
        }
      }
    }
    if (buffer.length > 0) {
      const item = acceptLine(buffer.endsWith("\r") ? buffer.slice(0, -1) : buffer);
      if (item !== undefined) {
        yield item;
      }
    }
    const finalItem = dispatch();
    if (finalItem !== undefined) {
      yield finalItem;
    }
    if (!terminal) {
      throw new LlmStreamProtocolError("The LLM stream ended without a terminal event.");
    }
  } catch {
    throw new LlmStreamProtocolError();
  } finally {
    reader.releaseLock();
  }
}

interface ValidatedEnvelope {
  readonly schemaVersion: string;
  readonly requestId: string;
  readonly sequence: number;
  readonly outcome?: LlmStreamTerminalOutcome;
}

function validateCanonicalEvent(value: unknown): ValidatedEnvelope {
  if (
    !isUnknownRecord(value) ||
    !hasOnlyKeys(value, ["schema_version", "request_id", "sequence", "payload"])
  ) {
    throw new LlmStreamProtocolError();
  }
  if (
    value.schema_version !== CANONICAL_SCHEMA_VERSION ||
    typeof value.request_id !== "string" ||
    value.request_id.length === 0 ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) < 0 ||
    !isUnknownRecord(value.payload) ||
    !hasOnlyKeys(value.payload, ["event", "data"])
  ) {
    throw new LlmStreamProtocolError();
  }
  const payloadEvent = value.payload.event;
  if (payloadEvent === "event") {
    if (!isUnknownRecord(value.payload.data) || typeof value.payload.data.event !== "string") {
      throw new LlmStreamProtocolError();
    }
    return {
      schemaVersion: value.schema_version,
      requestId: value.request_id,
      sequence: value.sequence as number,
    };
  }
  if (payloadEvent !== "terminal" || !isUnknownRecord(value.payload.data)) {
    throw new LlmStreamProtocolError();
  }
  const terminalValue = value.payload.data.state;
  const state =
    typeof terminalValue === "string"
      ? terminalValue
      : isUnknownRecord(terminalValue) && typeof terminalValue.state === "string"
        ? terminalValue.state
        : undefined;
  if (
    state === undefined ||
    TERMINAL_STATES[state as LlmStreamTerminalOutcome] !== true ||
    !Array.isArray(value.payload.data.accepted_public_content)
  ) {
    throw new LlmStreamProtocolError();
  }
  return {
    schemaVersion: value.schema_version,
    requestId: value.request_id,
    sequence: value.sequence as number,
    outcome: state as LlmStreamTerminalOutcome,
  };
}

function hasOnlyKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

interface ComposedSignal {
  readonly signal?: AbortSignal;
  readonly deadlineExpired: () => boolean;
  readonly cleanup: () => void;
}

function composeSignal(signal: AbortSignal | null | undefined, deadlineMs?: number): ComposedSignal {
  if (deadlineMs !== undefined && (!Number.isFinite(deadlineMs) || deadlineMs < 0)) {
    throw new RangeError("Request deadlineMs must be a finite non-negative number.");
  }
  if ((signal === undefined || signal === null) && deadlineMs === undefined) {
    return { deadlineExpired: () => false, cleanup: () => undefined };
  }
  const controller = new AbortController();
  let deadlineExpired = false;
  const forwardAbort = (): void => controller.abort(signal?.reason);
  if (signal?.aborted === true) {
    forwardAbort();
  } else {
    signal?.addEventListener("abort", forwardAbort, { once: true });
  }
  const timeout =
    deadlineMs === undefined
      ? undefined
      : setTimeout(() => {
          deadlineExpired = true;
          controller.abort(new DOMException("Deadline expired", "TimeoutError"));
        }, deadlineMs);
  return {
    signal: controller.signal,
    deadlineExpired: () => deadlineExpired,
    cleanup: () => {
      signal?.removeEventListener("abort", forwardAbort);
      clearTimeout(timeout);
    },
  };
}

async function openEventStream(
  client: ServiceClient,
  request: LlmRequest,
  options: LlmStreamOptions,
  composed: ComposedSignal,
): Promise<Response> {
  const configuration = client.configuration;
  const fetchImplementation = configuration.fetch ?? globalThis.fetch;
  if (typeof fetchImplementation !== "function") {
    throw new TypeError("LLM streaming requires fetch in this runtime.");
  }
  const { input, url } = joinPath(configuration.baseUrl, STREAM_PATH);
  const method = "POST";
  const context: ClientRequestContext = {
    url,
    method,
    ...(composed.signal === undefined ? {} : { signal: composed.signal }),
  };
  const headers = new Headers(
    typeof configuration.headers === "function"
      ? await configuration.headers(context)
      : configuration.headers,
  );
  new Headers(options.headers).forEach((value, name) => headers.set(name, value));
  if (configuration.auth !== undefined) {
    const authorization = await configuration.auth.authorize(context);
    new Headers(authorization.headers).forEach((value, name) => headers.set(name, value));
  }
  headers.set("Accept", "text/event-stream");
  headers.set("Content-Type", "application/json");
  if (options.idempotencyKey !== undefined) {
    headers.set(IDEMPOTENCY_KEY_HEADER, parseIdempotencyKey(options.idempotencyKey));
  }
  if (options.tenantId !== undefined) {
    validateUuidV7(options.tenantId, "tenantId");
    headers.set("X-Omnius-Tenant-Id", options.tenantId);
  }
  const requestPolicy =
    options.retryPolicy === false ? undefined : (options.retryPolicy ?? configuration.retryPolicy);
  if (requestPolicy !== undefined) {
    validateRetryPolicy(requestPolicy);
  }
  const idempotencyKey = headers.get(IDEMPOTENCY_KEY_HEADER) ?? undefined;
  let body: string;
  try {
    body = JSON.stringify(request);
  } catch (error: unknown) {
    throw new TypeError("The canonical LLM request could not be serialized.", { cause: error });
  }
  let attempt = 1;
  for (;;) {
    try {
      const response = await fetchImplementation(input, {
        method,
        headers,
        body,
        credentials: options.credentials ?? configuration.credentials ?? "same-origin",
        redirect: options.redirect ?? "error",
        ...(composed.signal === undefined ? {} : { signal: composed.signal }),
      });
      checkContract(response, configuration);
      if (response.ok) {
        return response;
      }
      const requestId = responseRequestId(response.headers);
      const error = new LlmStreamHttpError(response.status, requestId);
      const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"));
      if (
        requestPolicy === undefined ||
        !shouldRetryRequest({
          method,
          attempt,
          error: {
            retryable: error.retryable,
            ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
          },
          policy: requestPolicy,
          ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
        })
      ) {
        throw error;
      }
      await response.body?.cancel();
      await awaitRetryDelay(
        retryDelayMs(attempt, requestPolicy, retryAfterMs),
        composed,
        options.deadlineMs,
      );
      attempt += 1;
    } catch (error: unknown) {
      if (error instanceof LlmStreamHttpError || error instanceof ContractMismatchError) {
        throw error;
      }
      if (composed.signal?.aborted === true || isAbort(error)) {
        throw new AbortedRequestError(
          composed.deadlineExpired() ? "deadline" : "caller",
          options.deadlineMs,
          { cause: error },
        );
      }
      const normalized = new NetworkRequestError({ cause: error });
      if (
        requestPolicy === undefined ||
        !shouldRetryRequest({
          method,
          attempt,
          error: normalized,
          policy: requestPolicy,
          ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
        })
      ) {
        throw normalized;
      }
      await awaitRetryDelay(retryDelayMs(attempt, requestPolicy), composed, options.deadlineMs);
      attempt += 1;
    }
  }
}

function checkContract(
  response: Response,
  configuration: ServiceClient["configuration"],
): void {
  const raw = response.headers.get(RUNTIME_CONTRACT_HASH_HEADER)?.trim();
  if (raw === undefined || raw.length === 0) {
    return;
  }
  const runtimeContractHash = /^[0-9a-f]{64}$/u.test(raw) ? `sha256:${raw}` : raw;
  if (runtimeContractHash === GENERATED_AGAINST_CONTRACT_HASH) {
    return;
  }
  const minimum = response.headers.get(RUNTIME_MINIMUM_SDK_HEADER);
  const maximum = response.headers.get(RUNTIME_MAXIMUM_SDK_HEADER);
  const requestId = responseRequestId(response.headers);
  const mismatch = Object.freeze({
    generatedAgainst: GENERATED_AGAINST_CONTRACT_HASH,
    runtimeContractHash,
    ...(minimum === null ? {} : { runtimeMinimumSdkVersion: minimum }),
    ...(maximum === null ? {} : { runtimeMaximumSdkVersion: maximum }),
    ...(requestId === undefined ? {} : { requestId }),
  });
  try {
    configuration.onContractMismatch?.(mismatch);
  } catch {
    // Diagnostic callbacks cannot change stream behavior.
  }
  throw new ContractMismatchError(mismatch);
}

function joinPath(baseUrl: string, path: string): { readonly input: string | URL; readonly url: URL } {
  const root = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  if (baseUrl.startsWith("/")) {
    const input = `${root}${path}`;
    const origin =
      typeof globalThis.location === "undefined"
        ? "https://same-origin.omnius.invalid"
        : globalThis.location.origin;
    return { input, url: new URL(input, origin) };
  }
  const input = new URL(`${root}${path}`);
  return { input, url: input };
}

function responseRequestId(headers: Headers): string | undefined {
  for (const name of ["x-request-id", "request-id"] as const) {
    const value = headers.get(name)?.trim();
    if (value !== undefined && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function positiveBound(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer.`);
  }
  return value;
}

function validateUuidV7(value: string, name: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)) {
    throw new TypeError(`${name} must be a canonical UUIDv7.`);
  }
}

function isAbort(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    (error.name === "AbortError" || error.name === "TimeoutError")
  );
}

async function awaitRetryDelay(
  milliseconds: number,
  composed: ComposedSignal,
  deadlineMs: number | undefined,
): Promise<void> {
  try {
    await delay(milliseconds, composed.signal);
  } catch (error: unknown) {
    throw new AbortedRequestError(
      composed.deadlineExpired() ? "deadline" : "caller",
      deadlineMs,
      { cause: error },
    );
  }
}

async function delay(milliseconds: number, signal: AbortSignal | undefined): Promise<void> {
  if (milliseconds === 0) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const cleanup = (): void => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    };
    const complete = (): void => {
      cleanup();
      resolve();
    };
    const abort = (): void => {
      cleanup();
      reject(signal?.reason ?? new DOMException("Aborted", "AbortError"));
    };
    timeout = setTimeout(complete, milliseconds);
    if (signal?.aborted === true) {
      abort();
    } else {
      signal?.addEventListener("abort", abort, { once: true });
    }
  });
}

export type { RetryPolicy };
