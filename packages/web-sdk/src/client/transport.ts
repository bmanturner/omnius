import type { AuthAdapter } from "./auth.js";
import { GENERATED_AGAINST_CONTRACT_HASH } from "../internal/generated/contract-metadata.js";
import { IDEMPOTENCY_KEY_HEADER } from "./idempotency.js";
import { normalizePublicBasePath } from "./public-base.js";
import { isUnknownRecord } from "./type-guards.js";
import {
  retryDelayMs,
  shouldRetryRequest,
  validateRetryPolicy,
  type RetryPolicy,
} from "./retry.js";

export const RUNTIME_CONTRACT_HASH_HEADER = "X-Omnius-Contract-Hash" as const;
export const RUNTIME_MINIMUM_SDK_HEADER = "X-Omnius-Minimum-Sdk-Version" as const;
export const RUNTIME_MAXIMUM_SDK_HEADER = "X-Omnius-Maximum-Sdk-Version" as const;

export interface ClientRequestContext {
  readonly url: URL;
  readonly method: string;
  readonly signal?: AbortSignal;
}

export type ClientHeaders =
  | HeadersInit
  | ((context: ClientRequestContext) => HeadersInit | Promise<HeadersInit>);

export interface ProblemFieldViolation {
  readonly code: string;
  readonly message: string;
  readonly pointer: string;
}

export interface ClientProblemNotification {
  readonly status: number;
  readonly type: string;
  readonly code: string;
  readonly title: string;
  readonly detail?: string;
  readonly fieldViolations: readonly ProblemFieldViolation[];
  readonly requestId?: string;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
}

export interface ContractMismatchNotification {
  readonly generatedAgainst: string;
  readonly runtimeContractHash: string;
  readonly runtimeMinimumSdkVersion?: string;
  readonly runtimeMaximumSdkVersion?: string | null;
  readonly requestId?: string;
}

export interface ServiceClientConfiguration {
  readonly baseUrl: string | URL;
  readonly credentials?: RequestCredentials;
  readonly headers?: ClientHeaders;
  readonly fetch?: typeof globalThis.fetch;
  readonly auth?: AuthAdapter;
  readonly retryPolicy?: RetryPolicy;
  readonly onProblem?: (problem: ClientProblemNotification) => void;
  readonly onContractMismatch?: (mismatch: ContractMismatchNotification) => void;
}

export type DefinedServiceClientConfiguration = Omit<
  ServiceClientConfiguration,
  "baseUrl" | "retryPolicy"
> & {
  readonly baseUrl: string;
  readonly retryPolicy?: Readonly<RetryPolicy>;
};

export interface ServiceRequestOptions extends RequestInit {
  /** Overall request deadline, including auth, retries, and retry delays. */
  readonly deadlineMs?: number;
  /** Overrides the factory policy for this request; false disables retries. */
  readonly retryPolicy?: RetryPolicy | false;
}

export interface ServiceResponse<T> {
  readonly data: T;
  readonly status: number;
  readonly headers: Headers;
}

export interface ServiceClient {
  readonly configuration: Readonly<DefinedServiceClientConfiguration>;
  request<T>(path: string, options?: ServiceRequestOptions): Promise<ServiceResponse<T>>;
  /** Binds this client to generated HTTP/query options without mutable global configuration. */
  requestOptions(options?: ServiceRequestOptions): ServiceRequestOptions;
}

export type ServiceClientErrorKind =
  | "configuration"
  | "problem"
  | "network"
  | "aborted"
  | "invalid-response"
  | "contract-mismatch";

export abstract class ServiceClientError extends Error {
  readonly kind: ServiceClientErrorKind;
  readonly retryable: boolean;
  readonly requestId?: string;

  protected constructor(
    message: string,
    kind: ServiceClientErrorKind,
    retryable: boolean,
    requestId: string | undefined,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.kind = kind;
    this.retryable = retryable;
    if (requestId !== undefined) {
      this.requestId = requestId;
    }
  }
}

export class ServiceClientConfigurationError extends ServiceClientError {
  override readonly name = "ServiceClientConfigurationError";

  constructor(message: string, options?: ErrorOptions) {
    super(message, "configuration", false, undefined, options);
  }
}

export class ServiceProblemError extends ServiceClientError {
  override readonly name = "ServiceProblemError";
  readonly status: number;
  readonly type: string;
  readonly code: string;
  readonly title: string;
  readonly detail?: string;
  readonly fieldViolations: readonly ProblemFieldViolation[];
  readonly retryAfterMs?: number;
  readonly body: Readonly<Record<string, unknown>>;

  constructor(notification: ClientProblemNotification, body: Readonly<Record<string, unknown>>) {
    super(
      `${notification.title} (HTTP ${String(notification.status)})`,
      "problem",
      notification.retryable,
      notification.requestId,
    );
    this.status = notification.status;
    this.type = notification.type;
    this.code = notification.code;
    this.title = notification.title;
    if (notification.detail !== undefined) {
      this.detail = notification.detail;
    }
    this.fieldViolations = notification.fieldViolations;
    if (notification.retryAfterMs !== undefined) {
      this.retryAfterMs = notification.retryAfterMs;
    }
    this.body = body;
  }
}

export class NetworkRequestError extends ServiceClientError {
  override readonly name = "NetworkRequestError";

  constructor(options?: ErrorOptions) {
    super("The service request failed before receiving an HTTP response.", "network", true, undefined, options);
  }
}

export class AbortedRequestError extends ServiceClientError {
  override readonly name = "AbortedRequestError";
  readonly reason: "caller" | "deadline";
  readonly deadlineMs?: number;

  constructor(reason: "caller" | "deadline", deadlineMs: number | undefined, options?: ErrorOptions) {
    super(
      reason === "deadline" ? "The service request deadline expired." : "The service request was aborted.",
      "aborted",
      false,
      undefined,
      options,
    );
    this.reason = reason;
    if (deadlineMs !== undefined) {
      this.deadlineMs = deadlineMs;
    }
  }
}

export class InvalidResponseError extends ServiceClientError {
  override readonly name = "InvalidResponseError";
  readonly status: number;

  constructor(status: number, message: string, requestId?: string, options?: ErrorOptions) {
    super(message, "invalid-response", false, requestId, options);
    this.status = status;
  }
}

export class ContractMismatchError extends ServiceClientError {
  override readonly name = "ContractMismatchError";
  readonly mismatch: Readonly<ContractMismatchNotification>;

  constructor(mismatch: Readonly<ContractMismatchNotification>) {
    super(
      "The service runtime contract does not match the contract used to generate this SDK.",
      "contract-mismatch",
      false,
      mismatch.requestId,
    );
    this.mismatch = mismatch;
  }
}

/** Validates and canonicalizes an HTTP(S) absolute or same-origin root-relative base URL. */
export function normalizeServiceBaseUrl(baseUrl: string | URL): string {
  const value = baseUrl instanceof URL ? baseUrl.href : baseUrl;
  if (value.length === 0 || value.trim() !== value) {
    throw new TypeError("Service base URL must be a non-empty value without surrounding whitespace.");
  }
  if (value.startsWith("/")) {
    return normalizePublicBasePath(value);
  }

  let parsedAbsolute: URL;
  try {
    parsedAbsolute = new URL(value);
  } catch (error: unknown) {
    throw new TypeError("Service base URL must be HTTP(S) absolute or root-relative.", {
      cause: error,
    });
  }
  if (parsedAbsolute.protocol !== "http:" && parsedAbsolute.protocol !== "https:") {
    throw new TypeError("Service base URL must use HTTP or HTTPS.");
  }
  if (parsedAbsolute.username.length > 0 || parsedAbsolute.password.length > 0) {
    throw new TypeError("Service base URL must not contain credentials.");
  }
  if (parsedAbsolute.search.length > 0 || parsedAbsolute.hash.length > 0) {
    throw new TypeError("Service base URL must not include a query string or fragment.");
  }
  return parsedAbsolute.pathname === "/"
    ? parsedAbsolute.href
    : parsedAbsolute.href.replace(/\/$/u, "");
}

/** Returns a top-level immutable configuration snapshot suitable for client construction. */
export function defineServiceClientConfiguration(
  configuration: ServiceClientConfiguration,
): Readonly<DefinedServiceClientConfiguration> {
  if (configuration.retryPolicy !== undefined) {
    validateRetryPolicy(configuration.retryPolicy);
  }
  return Object.freeze({
    ...configuration,
    baseUrl: normalizeServiceBaseUrl(configuration.baseUrl),
    ...(configuration.retryPolicy === undefined
      ? {}
      : { retryPolicy: Object.freeze({ ...configuration.retryPolicy }) }),
  });
}

const serviceTransport = Symbol("omnius.service-transport");

interface BoundServiceRequestOptions extends ServiceRequestOptions {
  readonly [serviceTransport]: ServiceTransport;
}

interface ServiceTransport {
  readonly configuration: Readonly<DefinedServiceClientConfiguration>;
  execute<T>(path: string, options: ServiceRequestOptions): Promise<ServiceResponse<T>>;
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
  if (signal === undefined || signal === null) {
    if (deadlineMs === undefined) {
      return { deadlineExpired: () => false, cleanup: () => undefined };
    }
  }

  const controller = new AbortController();
  let deadlineExpired = false;
  const forwardAbort = (): void => controller.abort(signal?.reason);
  if (signal?.aborted === true) {
    forwardAbort();
  } else {
    signal?.addEventListener("abort", forwardAbort, { once: true });
  }
  if (deadlineMs === 0) {
    deadlineExpired = true;
    controller.abort(new DOMException("Deadline expired", "TimeoutError"));
  }
  const timeout =
    deadlineMs === undefined || deadlineMs === 0
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

function joinServicePath(baseUrl: string, path: string): { readonly input: string | URL; readonly url: URL } {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("#")) {
    throw new ServiceClientConfigurationError(
      "Generated service paths must be root-relative and must not contain fragments.",
    );
  }
  const root = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  if (baseUrl.startsWith("/")) {
    const input = `${root === "" ? "" : root}${path}`;
    const origin =
      typeof globalThis.location === "undefined"
        ? "https://same-origin.omnius.invalid"
        : globalThis.location.origin;
    return { input, url: new URL(input, origin) };
  }
  const input = new URL(`${root}${path}`);
  return { input, url: input };
}

function responseRequestId(headers: Headers, body?: Readonly<Record<string, unknown>>): string | undefined {
  for (const name of ["x-request-id", "request-id"] as const) {
    const value = headers.get(name)?.trim();
    if (value !== undefined && value.length > 0) {
      return value;
    }
  }
  const bodyValue = body?.request_id;
  return typeof bodyValue === "string" && bodyValue.length > 0 ? bodyValue : undefined;
}

export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
  if (value === null) {
    return undefined;
  }
  const trimmed = value.trim();
  if (/^[0-9]+$/u.test(trimmed)) {
    const seconds = Number(trimmed);
    return Number.isSafeInteger(seconds) ? seconds * 1_000 : undefined;
  }
  const date = Date.parse(trimmed);
  return Number.isFinite(date) ? Math.max(0, date - now) : undefined;
}


function problemRetryable(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status === 502 || status === 503 || status === 504;
}

function normalizeProblem(
  response: Response,
  body: unknown,
): { readonly notification: ClientProblemNotification; readonly body: Readonly<Record<string, unknown>> } {
  const requestId = responseRequestId(response.headers, isUnknownRecord(body) ? body : undefined);
  if (
    !isUnknownRecord(body) ||
    typeof body.type !== "string" ||
    typeof body.title !== "string" ||
    typeof body.status !== "number" ||
    body.status !== response.status ||
    typeof body.code !== "string"
  ) {
    throw new InvalidResponseError(
      response.status,
      "The service returned malformed RFC 9457 problem details.",
      requestId,
    );
  }
  const fieldViolations: ProblemFieldViolation[] = [];
  if (body.errors !== undefined && body.errors !== null) {
    if (!Array.isArray(body.errors)) {
      throw new InvalidResponseError(
        response.status,
        "The service returned malformed RFC 9457 field violations.",
        requestId,
      );
    }
    for (const item of body.errors) {
      if (
        !isUnknownRecord(item) ||
        typeof item.code !== "string" ||
        typeof item.message !== "string" ||
        typeof item.pointer !== "string"
      ) {
        throw new InvalidResponseError(
          response.status,
          "The service returned malformed RFC 9457 field violations.",
          requestId,
        );
      }
      fieldViolations.push(
        Object.freeze({ code: item.code, message: item.message, pointer: item.pointer }),
      );
    }
  }
  const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"));
  const notification: ClientProblemNotification = Object.freeze({
    status: response.status,
    type: body.type,
    code: body.code,
    title: body.title,
    ...(typeof body.detail === "string" ? { detail: body.detail } : {}),
    fieldViolations: Object.freeze(fieldViolations),
    ...(requestId === undefined ? {} : { requestId }),
    retryable: problemRetryable(response.status),
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
  });
  return { notification, body: Object.freeze({ ...body }) };
}

function notifySafely<T>(callback: ((value: T) => void) | undefined, value: T): void {
  try {
    callback?.(value);
  } catch {
    // Observability callbacks must never change transport behavior.
  }
}

function checkContractCompatibility(
  response: Response,
  configuration: Readonly<DefinedServiceClientConfiguration>,
): void {
  const runtimeValue = response.headers.get(RUNTIME_CONTRACT_HASH_HEADER)?.trim();
  if (runtimeValue === undefined || runtimeValue.length === 0) {
    return;
  }
  const runtimeContractHash = /^[0-9a-f]{64}$/u.test(runtimeValue)
    ? `sha256:${runtimeValue}`
    : runtimeValue;
  if (runtimeContractHash === GENERATED_AGAINST_CONTRACT_HASH) {
    return;
  }
  const requestId = responseRequestId(response.headers);
  const minimum = response.headers.get(RUNTIME_MINIMUM_SDK_HEADER);
  const maximum = response.headers.get(RUNTIME_MAXIMUM_SDK_HEADER);
  const mismatch: Readonly<ContractMismatchNotification> = Object.freeze({
    generatedAgainst: GENERATED_AGAINST_CONTRACT_HASH,
    runtimeContractHash,
    ...(minimum === null ? {} : { runtimeMinimumSdkVersion: minimum }),
    ...(maximum === null ? {} : { runtimeMaximumSdkVersion: maximum.length === 0 ? null : maximum }),
    ...(requestId === undefined ? {} : { requestId }),
  });
  notifySafely(configuration.onContractMismatch, mismatch);
  throw new ContractMismatchError(mismatch);
}

async function parseResponse<T>(
  response: Response,
  method: string,
  configuration: Readonly<DefinedServiceClientConfiguration>,
): Promise<ServiceResponse<T>> {
  checkContractCompatibility(response, configuration);
  const noBody =
    method === "HEAD" ||
    response.status === 204 ||
    response.status === 205 ||
    response.status === 304;
  if (noBody) {
    return { data: undefined as T, status: response.status, headers: response.headers };
  }

  const requestId = responseRequestId(response.headers);
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  const isJson = contentType === "application/json" || contentType?.endsWith("+json") === true;
  if (!isJson) {
    throw new InvalidResponseError(
      response.status,
      "The service returned a body with an unsupported content type.",
      requestId,
    );
  }
  const text = await response.text();
  if (text.length === 0) {
    throw new InvalidResponseError(response.status, "The service returned an empty JSON body.", requestId);
  }
  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch (error: unknown) {
    throw new InvalidResponseError(
      response.status,
      "The service returned malformed JSON.",
      requestId,
      { cause: error },
    );
  }
  if (!response.ok && contentType === "application/problem+json") {
    const problem = normalizeProblem(response, body);
    notifySafely(configuration.onProblem, problem.notification);
    throw new ServiceProblemError(problem.notification, problem.body);
  }
  return { data: body as T, status: response.status, headers: response.headers };
}

function normalizeThrownError(
  error: unknown,
  composed: ComposedSignal,
  deadlineMs: number | undefined,
): ServiceClientError {
  if (error instanceof ServiceClientError) {
    return error;
  }
  const errorName =
    isUnknownRecord(error) && typeof error.name === "string" ? error.name : undefined;
  if (composed.signal?.aborted === true || errorName === "AbortError" || errorName === "TimeoutError") {
    return new AbortedRequestError(
      composed.deadlineExpired() ? "deadline" : "caller",
      deadlineMs,
      { cause: error },
    );
  }
  return new NetworkRequestError({ cause: error });
}

async function delayWithSignal(delayMs: number, signal: AbortSignal | undefined): Promise<void> {
  if (delayMs === 0) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, delayMs);
    const abort = (): void => {
      clearTimeout(timeout);
      reject(signal?.reason ?? new DOMException("Aborted", "AbortError"));
    };
    if (signal?.aborted === true) {
      abort();
    } else {
      signal?.addEventListener("abort", abort, { once: true });
    }
  });
}

function createTransport(
  configuration: Readonly<DefinedServiceClientConfiguration>,
): ServiceTransport {
  const fetchImplementation = configuration.fetch ?? globalThis.fetch;
  if (typeof fetchImplementation !== "function") {
    throw new ServiceClientConfigurationError(
      "createServiceClient requires an injected fetch in runtimes without global fetch.",
    );
  }

  return Object.freeze({
    configuration,
    async execute<T>(path: string, options: ServiceRequestOptions): Promise<ServiceResponse<T>> {
      const { input, url } = joinServicePath(configuration.baseUrl, path);
      const method = (options.method ?? "GET").toUpperCase();
      const composed = composeSignal(options.signal, options.deadlineMs);
      try {
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
        const requestPolicy =
          options.retryPolicy === false ? undefined : (options.retryPolicy ?? configuration.retryPolicy);
        if (requestPolicy !== undefined) {
          validateRetryPolicy(requestPolicy);
        }
        const idempotencyKey = headers.get(IDEMPOTENCY_KEY_HEADER) ?? undefined;
        const internalOptions = options as Partial<BoundServiceRequestOptions>;
        const {
          deadlineMs: _deadlineMs,
          retryPolicy: _retryPolicy,
          [serviceTransport]: _boundTransport,
          ...requestInit
        } = internalOptions;
        let attempt = 1;
        for (;;) {
          try {
            const response = await fetchImplementation(input, {
              ...requestInit,
              method,
              headers,
              credentials: options.credentials ?? configuration.credentials ?? "same-origin",
              ...(composed.signal === undefined ? {} : { signal: composed.signal }),
            });
            return await parseResponse<T>(response, method, configuration);
          } catch (error: unknown) {
            const normalized = normalizeThrownError(error, composed, options.deadlineMs);
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
            try {
              await delayWithSignal(
                retryDelayMs(attempt, requestPolicy, normalized instanceof ServiceProblemError ? normalized.retryAfterMs : undefined),
                composed.signal,
              );
            } catch (delayError: unknown) {
              throw normalizeThrownError(delayError, composed, options.deadlineMs);
            }
            attempt += 1;
          }
        }
      } finally {
        composed.cleanup();
      }
    },
  });
}

export function createServiceClient(configuration: ServiceClientConfiguration): ServiceClient {
  const defined = defineServiceClientConfiguration(configuration);
  const transport = createTransport(defined);
  return Object.freeze({
    configuration: defined,
    request<T>(path: string, options: ServiceRequestOptions = {}): Promise<ServiceResponse<T>> {
      return transport.execute<T>(path, options);
    },
    requestOptions(options: ServiceRequestOptions = {}): ServiceRequestOptions {
      const bound: BoundServiceRequestOptions = { ...options, [serviceTransport]: transport };
      return Object.freeze(bound);
    },
  });
}

export function executeBoundServiceRequest<T>(
  path: string,
  options: RequestInit,
): Promise<ServiceResponse<T>> {
  const bound = options as Partial<BoundServiceRequestOptions>;
  const transport = bound[serviceTransport];
  if (transport === undefined) {
    throw new ServiceClientConfigurationError(
      "Generated service operations require options from createServiceClient().requestOptions().",
    );
  }
  return transport.execute<T>(path, bound);
}
