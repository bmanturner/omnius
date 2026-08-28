import {
  AbortedRequestError,
  NetworkRequestError,
  ServiceProblemError,
  type ClientRequestContext,
  type ServiceClient,
} from "../client/transport.js";
import {
  UploadPortError,
  browserUploadTransfer,
  type BrowserUploadTarget,
  type UploadAbandonRequest,
  type UploadFinalizeRequest,
  type UploadInitiation,
  type UploadPhase,
  type UploadInitiationRequest,
  type UploadPart,
  type UploadPorts,
  type UploadRejection,
  type UploadRemoteStatus,
  type UploadStatusRequest,
  type UploadTransferPlan,
  type UploadTransferRequest,
} from "./index.js";
const REMOTE_STATES: Readonly<Record<string, true>> = Object.freeze({
  pending: true,
  quarantined: true,
  available: true,
  rejected: true,
  deleted: true,
});
const ERROR_CODE_BY_PHASE: Readonly<Record<UploadPhase, UploadRejection["code"]>> = Object.freeze({
  checksum: "checksum",
  initiate: "validation",
  transfer: "transfer",
  finalize: "finalize",
  scan: "scan",
  cleanup: "state",
});
const TENANT_HEADER = "X-Omnius-Tenant-Id";
const IDEMPOTENCY_HEADER = "Idempotency-Key";

export interface HttpUploadPortsConfiguration {
  readonly client: ServiceClient;
  readonly tenantId: string | (() => string);
  /** Defaults to the real XMLHttpRequest adapter, preserving upload progress and cancellation. */
  readonly transfer?: Pick<UploadPorts, "transfer">;
}

/** Creates concrete authenticated HTTP ports for the server's tenant-scoped upload routes. */
export function createHttpUploadPorts(configuration: HttpUploadPortsConfiguration): UploadPorts {
  const tenantId = (): string => {
    const value = typeof configuration.tenantId === "function" ? configuration.tenantId() : configuration.tenantId;
    if (value.trim().length === 0 || value.trim() !== value) {
      throw portError("authorization", "initiate", false, "No active tenant is selected.");
    }
    return value;
  };
  const transferPort = configuration.transfer ?? browserUploadTransfer;

  return Object.freeze({
    async initiate(request: UploadInitiationRequest, signal: AbortSignal): Promise<UploadInitiation> {
      try {
        const response = await configuration.client.request<unknown>("/uploads", {
          method: "POST",
          signal,
          retryPolicy: false,
          headers: jsonHeaders(tenantId(), request.identity.idempotencyKey),
          body: JSON.stringify({
            identity: request.identity,
            fileName: request.fileName,
            ...(request.mediaType === undefined ? {} : { mediaType: request.mediaType }),
            byteLength: request.byteLength,
            sha256: request.sha256,
          }),
        });
        return parseInitiation(response.data, configuration.client.configuration.baseUrl);
      } catch (error: unknown) {
        throw mapHttpError(error, "initiate", signal);
      }
    },

    async transfer(request: UploadTransferRequest) {
      try {
        if (request.mode === "direct") return await transferPort.transfer(request);
        const target = await authorizedProxyTarget(configuration.client, request);
        return await transferPort.transfer({
          ...request,
          part: Object.freeze({ ...request.part, target }),
        });
      } catch (error: unknown) {
        if (error instanceof UploadPortError) throw error;
        throw mapHttpError(error, "transfer", request.signal);
      }
    },

    async finalize(request: UploadFinalizeRequest): Promise<UploadRemoteStatus> {
      try {
        const response = await configuration.client.request<unknown>(
          `/uploads/${encodeURIComponent(request.uploadId)}/complete`,
          {
            method: "POST",
            signal: request.signal,
            retryPolicy: false,
            headers: jsonHeaders(tenantId(), request.identity.idempotencyKey),
            body: JSON.stringify({
              identity: request.identity,
              sha256: request.sha256,
              parts: request.parts,
            }),
          },
        );
        return parseStatus(response.data);
      } catch (error: unknown) {
        throw mapHttpError(error, "finalize", request.signal);
      }
    },

    async getStatus(request: UploadStatusRequest): Promise<UploadRemoteStatus> {
      try {
        const response = await configuration.client.request<unknown>(
          `/uploads/${encodeURIComponent(request.uploadId)}/status`,
          {
            method: "POST",
            signal: request.signal,
            retryPolicy: false,
            headers: jsonHeaders(tenantId()),
            body: JSON.stringify({ identity: request.identity }),
          },
        );
        return parseStatus(response.data);
      } catch (error: unknown) {
        throw mapHttpError(error, "scan", request.signal);
      }
    },

    async abandon(request: UploadAbandonRequest): Promise<void> {
      try {
        await configuration.client.request<unknown>(
          `/uploads/${encodeURIComponent(request.uploadId)}/abandon`,
          {
            method: "POST",
            signal: request.signal,
            retryPolicy: false,
            headers: jsonHeaders(tenantId(), request.identity.idempotencyKey),
            body: JSON.stringify({ identity: request.identity }),
          },
        );
      } catch (error: unknown) {
        throw mapHttpError(error, "cleanup", request.signal);
      }
    },
  });
}

function jsonHeaders(tenantId: string, idempotencyKey?: string): Headers {
  const headers = new Headers({ "Content-Type": "application/json", [TENANT_HEADER]: tenantId });
  if (idempotencyKey !== undefined) headers.set(IDEMPOTENCY_HEADER, idempotencyKey);
  return headers;
}

async function authorizedProxyTarget(
  client: ServiceClient,
  request: UploadTransferRequest,
): Promise<BrowserUploadTarget> {
  const target = readBrowserTarget(request.part.target);
  const url = resolveUploadTarget(client.configuration.baseUrl, target.url);
  const context: ClientRequestContext = { url: new URL(url, browserOrigin()), method: target.method, signal: request.signal };
  const configured = typeof client.configuration.headers === "function"
    ? await client.configuration.headers(context)
    : client.configuration.headers;
  const headers = new Headers(configured);
  new Headers(target.headers).forEach((value, name) => headers.set(name, value));
  if (client.configuration.auth !== undefined) {
    const authorized = await client.configuration.auth.authorize(context);
    new Headers(authorized.headers).forEach((value, name) => headers.set(name, value));
  }
  return Object.freeze({
    ...target,
    url,
    headers: Object.freeze(Object.fromEntries(headers.entries())),
    withCredentials: client.configuration.credentials === "include",
  });
}

function resolveUploadTarget(baseUrl: string, target: string): string {
  if (/^https?:\/\//u.test(target)) return target;
  if (!target.startsWith("/") || target.startsWith("//")) {
    throw portError("validation", "initiate", false, "The upload service returned an invalid transfer target.");
  }
  if (baseUrl.startsWith("/")) {
    const root = baseUrl === "/" ? "" : (baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl);
    return `${root}${target}`;
  }
  const root = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  return new URL(`${new URL(root).pathname === "/" ? new URL(root).origin : root}${target}`).href;
}

function browserOrigin(): string {
  return typeof globalThis.location === "undefined" ? "https://same-origin.omnius.invalid" : globalThis.location.origin;
}

function parseInitiation(value: unknown, _baseUrl: string): UploadInitiation {
  const record = readRecord(value, "initiate");
  if (record.decision === "already-started") {
    return Object.freeze({
      decision: "already-started",
      uploadId: readString(record.uploadId, "initiate"),
      status: parseStatus(record.status),
    });
  }
  if (record.decision !== "started") {
    throw portError("validation", "initiate", false, "The upload service returned an invalid initiation decision.");
  }
  const transfer = readRecord(record.transfer, "initiate");
  if (transfer.mode !== "direct" && transfer.mode !== "proxied") {
    throw portError("validation", "initiate", false, "The upload service returned an invalid transfer mode.");
  }
  if (!Array.isArray(transfer.parts)) {
    throw portError("validation", "initiate", false, "The upload service returned an invalid transfer plan.");
  }
  const parts = transfer.parts.map((part): UploadPart => {
    const candidate = readRecord(part, "initiate");
    const target = readBrowserTarget(candidate.target);
    return Object.freeze({
      partNumber: readInteger(candidate.partNumber, "initiate"),
      offset: readInteger(candidate.offset, "initiate"),
      length: readInteger(candidate.length, "initiate"),
      target: Object.freeze(target),
    });
  });
  const plan: UploadTransferPlan = Object.freeze({ mode: transfer.mode, parts: Object.freeze(parts) });
  return Object.freeze({
    decision: "started",
    uploadId: readString(record.uploadId, "initiate"),
    transfer: plan,
  });
}

function parseStatus(value: unknown): UploadRemoteStatus {
  const record = readRecord(value, "scan");
  if (typeof record.state !== "string" || REMOTE_STATES[record.state] !== true) {
    throw portError("validation", "scan", false, "The upload service returned an invalid lifecycle state.");
  }
  const revision = record.revision === undefined ? undefined : readInteger(record.revision, "scan");
  const rejection = record.rejection === undefined ? undefined : parseRejection(record.rejection);
  return Object.freeze({ state: record.state as UploadRemoteStatus["state"], ...(revision === undefined ? {} : { revision }), ...(rejection === undefined ? {} : { rejection }) });
}

function parseRejection(value: unknown): UploadRejection {
  const record = readRecord(value, "scan");
  return Object.freeze({
    code: readString(record.code, "scan") as UploadRejection["code"],
    message: readString(record.message, "scan"),
    phase: readString(record.phase, "scan") as UploadRejection["phase"],
    retryable: typeof record.retryable === "boolean" ? record.retryable : false,
  });
}

function readBrowserTarget(value: unknown): BrowserUploadTarget {
  const record = readRecord(value, "initiate");
  if ((record.method !== "POST" && record.method !== "PUT") || typeof record.url !== "string") {
    throw portError("validation", "initiate", false, "The upload service returned an invalid transfer target.");
  }
  return record as unknown as BrowserUploadTarget;
}

function readRecord(value: unknown, phase: UploadRejection["phase"]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw portError("validation", phase, false, `The upload service returned an invalid ${phase} response.`);
  }
  return value as Record<string, unknown>;
}

function readString(value: unknown, phase: UploadRejection["phase"]): string {
  if (typeof value !== "string" || value.length === 0) {
    throw portError("validation", phase, false, `The upload service returned an invalid ${phase} response.`);
  }
  return value;
}

function readInteger(value: unknown, phase: UploadRejection["phase"]): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw portError("validation", phase, false, `The upload service returned an invalid ${phase} response.`);
  }
  return value;
}

function mapHttpError(error: unknown, phase: UploadPhase, signal: AbortSignal): UploadPortError | unknown {
  if (error instanceof UploadPortError) return error;
  if (signal.aborted) {
    return signal.reason ?? portError("cancelled", phase, true, "The upload request was cancelled.");
  }
  if (error instanceof ServiceProblemError) {
    if (error.status === 404) return portError("authorization", phase, false, "The upload is unavailable.", error);
    if (error.status === 409) return portError("identity-conflict", phase, false, "The upload identity conflicts with persisted state.", error);
    if (error.status === 400 || error.status === 413 || error.status === 422) {
      return portError("validation", phase, false, "The upload request was rejected.", error);
    }
    return portError(ERROR_CODE_BY_PHASE[phase], phase, error.retryable, "The upload service is temporarily unavailable.", error);
  }
  if (error instanceof NetworkRequestError) {
    return portError(ERROR_CODE_BY_PHASE[phase], phase, true, "The upload service could not be reached.", error);
  }
  if (error instanceof AbortedRequestError) {
    return portError("cancelled", phase, true, "The upload request was cancelled.", error);
  }
  return portError(ERROR_CODE_BY_PHASE[phase], phase, false, "The upload service returned an invalid response.", error);
}

function portError(
  code: UploadRejection["code"],
  phase: UploadPhase,
  retryable: boolean,
  message: string,
  cause?: unknown,
): UploadPortError {
  return new UploadPortError({ code, phase, retryable, message }, cause === undefined ? undefined : { cause });
}
