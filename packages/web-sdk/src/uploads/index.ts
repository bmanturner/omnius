export interface UploadSource {
  readonly data: Blob;
  readonly fileName: string;
  readonly mediaType?: string;
}

export interface UploadProgress {
  readonly bytesTransferred: number;
  readonly totalBytes: number;
  readonly fraction: number;
}

export type UploadPhase =
  | "checksum"
  | "initiate"
  | "transfer"
  | "finalize"
  | "scan"
  | "cleanup";

export type UploadRejectionCode =
  | "authorization"
  | "validation"
  | "unsupported"
  | "identity-conflict"
  | "checksum"
  | "transfer"
  | "finalize"
  | "scan"
  | "cancelled"
  | "retry-exhausted"
  | "remote-rejection"
  | "state";

export interface UploadRejection {
  readonly code: UploadRejectionCode;
  readonly message: string;
  readonly phase: UploadPhase;
  readonly retryable: boolean;
  readonly cause?: unknown;
}

export type UploadRemoteState = "pending" | "quarantined" | "available" | "rejected" | "deleted";

export interface UploadRemoteStatus {
  readonly state: UploadRemoteState;
  readonly revision?: number;
  readonly rejection?: UploadRejection;
}

export interface UploadWorkflowIdentity {
  /** Stable business-workflow key. It must never be reused for different bytes. */
  readonly workflowKey: string;
  /** Stable request idempotency key reused by every retry, including finalize retries. */
  readonly idempotencyKey: string;
}

export type BrowserUploadBody =
  | { readonly kind: "raw" }
  | {
      readonly kind: "form";
      readonly fields: Readonly<Record<string, string>>;
      readonly fileField: string;
    };

export interface BrowserUploadTarget {
  readonly url: string;
  readonly method: "POST" | "PUT";
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: BrowserUploadBody;
  readonly withCredentials?: boolean;
}

export interface UploadPart {
  readonly partNumber: number;
  readonly offset: number;
  readonly length: number;
  /** Opaque authorized destination. Browser adapters may use BrowserUploadTarget. */
  readonly target: unknown;
}

export interface UploadTransferPlan {
  readonly mode: "direct" | "proxied";
  readonly parts: readonly UploadPart[];
}

export interface StartedUpload {
  readonly decision: "started";
  readonly uploadId: string;
  readonly transfer: UploadTransferPlan;
  /** Parts durably acknowledged by an earlier attempt. */
  readonly completedParts?: readonly UploadPartReceipt[];
}

export interface AlreadyStartedUpload {
  readonly decision: "already-started";
  readonly uploadId: string;
  readonly status: UploadRemoteStatus;
}

export interface RejectedUploadInitiation {
  readonly decision: "rejected";
  readonly rejection: UploadRejection;
}

export type UploadInitiation =
  | StartedUpload
  | AlreadyStartedUpload
  | RejectedUploadInitiation;

export interface UploadInitiationRequest {
  readonly identity: UploadWorkflowIdentity;
  readonly fileName: string;
  readonly mediaType?: string;
  readonly byteLength: number;
  readonly sha256: string;
}

export interface UploadPartReceipt {
  readonly partNumber: number;
  readonly receipt: string;
}

export interface UploadTransferRequest {
  readonly identity: UploadWorkflowIdentity;
  readonly uploadId: string;
  readonly mode: UploadTransferPlan["mode"];
  readonly part: UploadPart;
  readonly bytes: Blob;
  readonly sha256: string;
  readonly signal: AbortSignal;
  readonly reportProgress: (bytesTransferred: number) => void;
}

export interface UploadFinalizeRequest {
  readonly identity: UploadWorkflowIdentity;
  readonly uploadId: string;
  readonly sha256: string;
  readonly parts: readonly UploadPartReceipt[];
  readonly signal: AbortSignal;
}

export interface UploadStatusRequest {
  readonly identity: UploadWorkflowIdentity;
  readonly uploadId: string;
  readonly signal: AbortSignal;
}

export interface UploadAbandonRequest {
  readonly identity: UploadWorkflowIdentity;
  readonly uploadId: string;
  readonly signal: AbortSignal;
}

export interface UploadPorts {
  /**
   * Must authorize and durably bind workflowKey, idempotencyKey, size, and digest before returning
   * any signed destination. Reusing a workflow key for different bytes must be rejected.
   */
  initiate(request: UploadInitiationRequest, signal: AbortSignal): Promise<UploadInitiation>;
  transfer(request: UploadTransferRequest): Promise<UploadPartReceipt>;
  /** Must independently authorize completion and be idempotent by identity.idempotencyKey. */
  finalize(request: UploadFinalizeRequest): Promise<UploadRemoteStatus>;
  getStatus(request: UploadStatusRequest): Promise<UploadRemoteStatus>;
  abandon(request: UploadAbandonRequest): Promise<void>;
}

export interface UploadChecksumPort {
  sha256(source: Blob, signal: AbortSignal): Promise<string>;
}

export interface UploadRetryPolicy {
  readonly maxAttempts: number;
  readonly delayMs: (attempt: number) => number;
}

export interface UploadCoordinatorOptions {
  readonly signal?: AbortSignal;
  readonly checksum?: UploadChecksumPort;
  readonly retry?: Partial<UploadRetryPolicy>;
  readonly scanPollIntervalMs?: number;
  readonly maxScanPolls?: number;
}

export type UploadState =
  | { readonly status: "idle"; readonly available: false }
  | { readonly status: "checksumming"; readonly available: false }
  | { readonly status: "initiating"; readonly available: false; readonly attempt: number }
  | {
      readonly status: "transferring";
      readonly available: false;
      readonly uploadId: string;
      readonly mode: UploadTransferPlan["mode"];
      readonly partNumber: number;
      readonly progress: UploadProgress;
    }
  | { readonly status: "finalizing"; readonly available: false; readonly uploadId: string }
  | {
      readonly status: "quarantined";
      readonly available: false;
      readonly uploadId: string;
      readonly pollCount: number;
    }
  | { readonly status: "available"; readonly available: true; readonly uploadId: string }
  | {
      readonly status: "rejected";
      readonly available: false;
      readonly uploadId?: string;
      readonly rejection: UploadRejection;
    }
  | {
      readonly status: "cancelled";
      readonly available: false;
      readonly uploadId?: string;
      readonly reason: string;
      readonly resumable: boolean;
    }
  | {
      readonly status: "failed";
      readonly available: false;
      readonly uploadId?: string;
      readonly rejection: UploadRejection;
    }
  | { readonly status: "abandoned"; readonly available: false; readonly uploadId: string }
  | {
      readonly status: "disposed";
      readonly available: false;
      readonly uploadId?: string;
      readonly abandoned: boolean;
      readonly cleanupRejection?: UploadRejection;
    };

export interface UploadBrowserSupport {
  readonly abort: boolean;
  readonly blobArrayBuffer: boolean;
  readonly sha256: boolean;
  readonly uploadProgress: boolean;
  readonly coordinatorSupported: boolean;
}

const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_SCAN_POLLS = 120;
const DEFAULT_SCAN_POLL_INTERVAL_MS = 1_000;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

/** Reports browser primitives without assuming that fetch exposes upload progress (it does not). */
export function detectUploadBrowserSupport(): UploadBrowserSupport {
  const blobArrayBuffer = typeof Blob !== "undefined" && "arrayBuffer" in Blob.prototype;
  const abort = typeof AbortController !== "undefined";
  const sha256 =
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle?.digest === "function";
  return Object.freeze({
    abort,
    blobArrayBuffer,
    sha256,
    uploadProgress: typeof XMLHttpRequest !== "undefined",
    coordinatorSupported: abort && blobArrayBuffer && sha256,
  });
}

/** Creates validated progress and defines an empty upload as already complete. */
export function calculateUploadProgress(
  bytesTransferred: number,
  totalBytes: number,
): UploadProgress {
  if (
    !Number.isSafeInteger(bytesTransferred) ||
    !Number.isSafeInteger(totalBytes) ||
    bytesTransferred < 0 ||
    totalBytes < 0 ||
    bytesTransferred > totalBytes
  ) {
    throw new RangeError(
      "Upload byte counts must be non-negative safe integers and transferred bytes cannot exceed total bytes.",
    );
  }

  return Object.freeze({
    bytesTransferred,
    totalBytes,
    fraction: totalBytes === 0 ? 1 : bytesTransferred / totalBytes,
  });
}

export function createUploadWorkflowIdentity(
  workflowKey: string,
  idempotencyKey: string,
): UploadWorkflowIdentity {
  if (workflowKey.trim().length === 0 || idempotencyKey.trim().length === 0) {
    throw new TypeError("Upload workflow and idempotency keys must be non-empty.");
  }
  return Object.freeze({ workflowKey, idempotencyKey });
}

export class UploadPortError extends Error {
  readonly code: UploadRejectionCode;
  readonly phase: UploadPhase;
  readonly retryable: boolean;

  constructor(rejection: Omit<UploadRejection, "cause">, options?: ErrorOptions) {
    super(rejection.message, options);
    this.name = "UploadPortError";
    this.code = rejection.code;
    this.phase = rejection.phase;
    this.retryable = rejection.retryable;
  }
}

function rejectionFrom(error: unknown, phase: UploadPhase): UploadRejection {
  if (error instanceof UploadPortError) {
    return Object.freeze({
      code: error.code,
      message: error.message,
      phase: error.phase,
      retryable: error.retryable,
      cause: error.cause,
    });
  }
  const codeByPhase: Readonly<Record<UploadPhase, UploadRejectionCode>> = {
    checksum: "checksum",
    initiate: "validation",
    transfer: "transfer",
    finalize: "finalize",
    scan: "scan",
    cleanup: "state",
  };
  return Object.freeze({
    code: codeByPhase[phase],
    message: error instanceof Error ? error.message : `Upload ${phase} failed.`,
    phase,
    retryable: false,
    cause: error,
  });
}

function cancelledRejection(reason: string): UploadRejection {
  return Object.freeze({
    code: "cancelled",
    message: reason,
    phase: "transfer",
    retryable: true,
  });
}

function assertSource(source: UploadSource): void {
  if (source.fileName.trim().length === 0) {
    throw new TypeError("Upload fileName must be non-empty.");
  }
  if (!Number.isSafeInteger(source.data.size) || source.data.size < 0) {
    throw new RangeError("Upload byte length must be a non-negative safe integer.");
  }
}

function assertPlan(plan: UploadTransferPlan, totalBytes: number): void {
  if (plan.parts.length === 0) {
    throw new UploadPortError({
      code: "validation",
      message: "The authorized upload plan contains no parts.",
      phase: "initiate",
      retryable: false,
    });
  }
  let expectedOffset = 0;
  const partNumbers = new Set<number>();
  for (const part of plan.parts) {
    if (
      !Number.isSafeInteger(part.partNumber) ||
      part.partNumber <= 0 ||
      partNumbers.has(part.partNumber) ||
      !Number.isSafeInteger(part.offset) ||
      !Number.isSafeInteger(part.length) ||
      !Number.isSafeInteger(part.offset + part.length) ||
      part.offset !== expectedOffset ||
      (part.length === 0 && !(totalBytes === 0 && plan.parts.length === 1)) ||
      part.length < 0 ||
      part.offset + part.length > totalBytes
    ) {
      throw new UploadPortError({
        code: "validation",
        message: "The authorized upload plan has invalid, duplicate, overlapping, or missing parts.",
        phase: "initiate",
        retryable: false,
      });
    }
    partNumbers.add(part.partNumber);
    expectedOffset += part.length;
  }
  if (expectedOffset !== totalBytes) {
    throw new UploadPortError({
      code: "validation",
      message: "The authorized upload plan does not cover the exact source byte length.",
      phase: "initiate",
      retryable: false,
    });
  }
}

function sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (milliseconds <= 0) return Promise.resolve();
  const { promise, resolve, reject } = Promise.withResolvers<void>();
  const finish = () => {
    signal.removeEventListener("abort", abort);
    resolve();
  };
  const timer = setTimeout(finish, milliseconds);
  const abort = () => {
    clearTimeout(timer);
    reject(signal.reason);
  };
  signal.addEventListener("abort", abort, { once: true });
  return promise;
}

const legalTransitions: Readonly<
  Record<UploadState["status"], readonly UploadState["status"][]>
> = {
  idle: ["checksumming", "initiating", "disposed"],
  checksumming: ["initiating", "cancelled", "failed", "disposed"],
  initiating: [
    "initiating",
    "transferring",
    "finalizing",
    "quarantined",
    "available",
    "rejected",
    "cancelled",
    "failed",
    "disposed",
  ],
  transferring: ["transferring", "finalizing", "cancelled", "failed", "disposed"],
  finalizing: [
    "finalizing",
    "quarantined",
    "available",
    "rejected",
    "cancelled",
    "failed",
    "disposed",
  ],
  quarantined: [
    "quarantined",
    "available",
    "rejected",
    "cancelled",
    "failed",
    "disposed",
  ],
  available: ["disposed"],
  rejected: ["disposed"],
  cancelled: ["initiating", "quarantined", "finalizing", "disposed"],
  failed: ["initiating", "quarantined", "finalizing", "disposed"],
  abandoned: ["disposed"],
  disposed: [],
};

export class UploadCoordinator {
  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  readonly getSnapshot = (): UploadState => this.currentState;
  readonly source: UploadSource;
  readonly identity: UploadWorkflowIdentity;

  private currentState: UploadState = Object.freeze({ status: "idle", available: false });
  private readonly listeners = new Set<() => void>();
  private readonly receipts = new Map<number, UploadPartReceipt>();
  private readonly checksum: UploadChecksumPort;
  private readonly retry: UploadRetryPolicy;
  private readonly maxScanPolls: number;
  private readonly scanPollIntervalMs: number;
  private readonly externalSignal: AbortSignal | undefined;
  private controller: AbortController | undefined;
  private active: Promise<UploadState> | undefined;
  private digest: string | undefined;
  private uploadId: string | undefined;
  private cancelReason = "Upload cancelled.";
  private finalizeEntered = false;
  private disposed = false;
  private started = false;
  private externalAbortListener: (() => void) | undefined;

  constructor(
    source: UploadSource,
    identity: UploadWorkflowIdentity,
    private readonly ports: UploadPorts,
    options: UploadCoordinatorOptions = {},
  ) {
    assertSource(source);
    this.source = Object.freeze({
      data: source.data,
      fileName: source.fileName,
      ...(source.mediaType === undefined ? {} : { mediaType: source.mediaType }),
    });
    this.identity = createUploadWorkflowIdentity(identity.workflowKey, identity.idempotencyKey);
    const maxAttempts = options.retry?.maxAttempts ?? DEFAULT_RETRY_ATTEMPTS;
    const maxScanPolls = options.maxScanPolls ?? DEFAULT_SCAN_POLLS;
    const scanPollIntervalMs = options.scanPollIntervalMs ?? DEFAULT_SCAN_POLL_INTERVAL_MS;
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
      throw new RangeError("Upload retry maxAttempts must be a positive safe integer.");
    }
    if (!Number.isSafeInteger(maxScanPolls) || maxScanPolls < 1) {
      throw new RangeError("Upload maxScanPolls must be a positive safe integer.");
    }
    if (!Number.isSafeInteger(scanPollIntervalMs) || scanPollIntervalMs < 0) {
      throw new RangeError("Upload scanPollIntervalMs must be a non-negative safe integer.");
    }
    this.checksum = options.checksum ?? browserChecksumPort;
    this.retry = {
      maxAttempts,
      delayMs: options.retry?.delayMs ?? ((attempt) => Math.min(250 * 2 ** (attempt - 1), 4_000)),
    };
    this.maxScanPolls = maxScanPolls;
    this.scanPollIntervalMs = scanPollIntervalMs;
    this.externalSignal = options.signal;
  }

  get state(): UploadState {
    return this.currentState;
  }

  start(): Promise<UploadState> {
    if (this.disposed) return Promise.reject(new Error("The upload coordinator is disposed."));
    if (this.started) return this.active ?? Promise.resolve(this.currentState);
    this.started = true;
    return this.beginRun();
  }

  resume(): Promise<UploadState> {
    if (this.disposed) return Promise.reject(new Error("The upload coordinator is disposed."));
    if (this.active !== undefined) return this.active;
    if (
      this.currentState.status !== "cancelled" &&
      !(this.currentState.status === "failed" && this.currentState.rejection.retryable)
    ) {
      return Promise.reject(new Error(`Upload cannot resume from ${this.currentState.status}.`));
    }
    return this.beginRun();
  }

  cancel(reason = "Upload cancelled."): void {
    if (this.disposed || this.active === undefined) return;
    this.cancelReason = reason;
    this.controller?.abort(cancelledRejection(reason));
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    this.controller?.abort(cancelledRejection("Upload coordinator disposed."));
    this.detachExternalSignal();
    const uploadId = this.uploadId;
    const needsAbandonment =
      uploadId !== undefined &&
      this.currentState.status !== "available" &&
      this.currentState.status !== "rejected" &&
      this.currentState.status !== "abandoned";
    let abandoned = false;
    let cleanupRejection: UploadRejection | undefined;
    if (needsAbandonment) {
      const cleanupController = new AbortController();
      try {
        await this.ports.abandon({
          identity: this.identity,
          uploadId,
          signal: cleanupController.signal,
        });
        abandoned = true;
        this.transition(
          Object.freeze({ status: "abandoned", available: false, uploadId }),
          true,
        );
      } catch (error) {
        cleanupRejection = rejectionFrom(error, "cleanup");
      }
    }
    this.transition(
      Object.freeze({
        status: "disposed",
        available: false,
        ...(uploadId === undefined ? {} : { uploadId }),
        abandoned,
        ...(cleanupRejection === undefined ? {} : { cleanupRejection }),
      }),
      true,
    );
    this.listeners.clear();
  }


  private beginRun(): Promise<UploadState> {
    this.controller = new AbortController();
    this.attachExternalSignal(this.controller);
    const running = this.run(this.controller.signal).finally(() => {
      if (this.active === running) this.active = undefined;
      this.detachExternalSignal();
    });
    this.active = running;
    return running;
  }

  private async run(signal: AbortSignal): Promise<UploadState> {
    try {
      if (this.digest === undefined) {
        this.transition(Object.freeze({ status: "checksumming", available: false }));
        this.digest = await this.checksum.sha256(this.source.data, signal);
        if (!SHA256_PATTERN.test(this.digest)) {
          throw new UploadPortError({
            code: "checksum",
            message: "The checksum port returned a non-canonical SHA-256 digest.",
            phase: "checksum",
            retryable: false,
          });
        }
      }
      if (signal.aborted) throw signal.reason;

      const initiation = await this.withRetry("initiate", signal, async (attempt) => {
        this.transition(Object.freeze({ status: "initiating", available: false, attempt }));
        return this.ports.initiate(
          {
            identity: this.identity,
            fileName: this.source.fileName,
            ...(this.source.mediaType === undefined ? {} : { mediaType: this.source.mediaType }),
            byteLength: this.source.data.size,
            sha256: this.digest as string,
          },
          signal,
        );
      });

      if (initiation.decision === "rejected") {
        this.transition(
          Object.freeze({ status: "rejected", available: false, rejection: initiation.rejection }),
        );
        return this.currentState;
      }
      this.bindUploadId(initiation.uploadId);
      if (initiation.decision === "already-started") {
        return this.acceptRemoteStatus(initiation.status, signal);
      }

      assertPlan(initiation.transfer, this.source.data.size);
      for (const receipt of initiation.completedParts ?? []) this.recordReceipt(receipt, initiation.transfer);
      let completedBytes = 0;
      for (const part of initiation.transfer.parts) {
        if (this.receipts.has(part.partNumber)) {
          completedBytes += part.length;
          this.transition(
            Object.freeze({
              status: "transferring",
              available: false,
              uploadId: initiation.uploadId,
              mode: initiation.transfer.mode,
              partNumber: part.partNumber,
              progress: calculateUploadProgress(completedBytes, this.source.data.size),
            }),
          );
          continue;
        }
        const baseBytes = completedBytes;
        let publishedPartProgress = 0;
        let lastAttemptProgress = 0;
        const receipt = await this.withRetry("transfer", signal, async () => {
          lastAttemptProgress = 0;
          return this.ports.transfer({
            identity: this.identity,
            uploadId: initiation.uploadId,
            mode: initiation.transfer.mode,
            part,
            bytes: this.source.data.slice(part.offset, part.offset + part.length),
            sha256: this.digest as string,
            signal,
            reportProgress: (partBytes) => {
              if (
                !Number.isSafeInteger(partBytes) ||
                partBytes < lastAttemptProgress ||
                partBytes > part.length
              ) {
                throw new RangeError(
                  "Upload part progress must be monotonic and within the part length.",
                );
              }
              lastAttemptProgress = partBytes;
              publishedPartProgress = Math.max(publishedPartProgress, partBytes);
              this.transition(
                Object.freeze({
                  status: "transferring",
                  available: false,
                  uploadId: initiation.uploadId,
                  mode: initiation.transfer.mode,
                  partNumber: part.partNumber,
                  progress: calculateUploadProgress(
                    baseBytes + publishedPartProgress,
                    this.source.data.size,
                  ),
                }),
              );
            },
          });
        });
        if (receipt.partNumber !== part.partNumber || receipt.receipt.length === 0) {
          throw new UploadPortError({
            code: "identity-conflict",
            message: "The transfer receipt does not belong to the requested upload part.",
            phase: "transfer",
            retryable: false,
          });
        }
        this.receipts.set(part.partNumber, Object.freeze(receipt));
        completedBytes += part.length;
        if (publishedPartProgress < part.length) {
          this.transition(
            Object.freeze({
              status: "transferring",
              available: false,
              uploadId: initiation.uploadId,
              mode: initiation.transfer.mode,
              partNumber: part.partNumber,
              progress: calculateUploadProgress(completedBytes, this.source.data.size),
            }),
          );
        }
      }

      this.finalizeEntered = true;
      this.transition(
        Object.freeze({ status: "finalizing", available: false, uploadId: initiation.uploadId }),
      );
      const status = await this.withRetry("finalize", signal, () =>
        this.ports.finalize({
          identity: this.identity,
          uploadId: initiation.uploadId,
          sha256: this.digest as string,
          parts: initiation.transfer.parts.map((part) => {
            const receipt = this.receipts.get(part.partNumber);
            if (receipt === undefined) {
              throw new UploadPortError({
                code: "state",
                message: "Finalize was attempted before every upload part was acknowledged.",
                phase: "finalize",
                retryable: false,
              });
            }
            return receipt;
          }),
          signal,
        }),
      );
      return this.acceptRemoteStatus(status, signal);
    } catch (error) {
      if (this.disposed) return this.currentState;
      if (signal.aborted) {
        this.transition(
          Object.freeze({
            status: "cancelled",
            available: false,
            ...(this.uploadId === undefined ? {} : { uploadId: this.uploadId }),
            reason: this.cancelReason,
            resumable: true,
          }),
        );
        return this.currentState;
      }
      const phase = this.phaseForState();
      const rejection = rejectionFrom(error, phase);
      this.transition(
        Object.freeze({
          status: "failed",
          available: false,
          ...(this.uploadId === undefined ? {} : { uploadId: this.uploadId }),
          rejection,
        }),
      );
      return this.currentState;
    }
  }

  private async acceptRemoteStatus(status: UploadRemoteStatus, signal: AbortSignal): Promise<UploadState> {
    const uploadId = this.uploadId;
    if (uploadId === undefined) throw new Error("Remote status received before upload identity.");
    if (status.state === "available") {
      this.transition(Object.freeze({ status: "available", available: true, uploadId }));
      return this.currentState;
    }
    if (status.state === "rejected" || status.state === "deleted") {
      const rejection =
        status.rejection ??
        Object.freeze({
          code: "remote-rejection" as const,
          message: "The upload was rejected by verification policy.",
          phase: "scan" as const,
          retryable: false,
        });
      this.transition(Object.freeze({ status: "rejected", available: false, uploadId, rejection }));
      return this.currentState;
    }

    for (let pollCount = 0; pollCount < this.maxScanPolls; pollCount += 1) {
      this.transition(
        Object.freeze({ status: "quarantined", available: false, uploadId, pollCount }),
      );
      await sleep(this.scanPollIntervalMs, signal);
      const next = await this.withRetry("scan", signal, () =>
        this.ports.getStatus({ identity: this.identity, uploadId, signal }),
      );
      if (next.state !== "quarantined") return this.acceptRemoteStatus(next, signal);
    }
    throw new UploadPortError({
      code: "scan",
      message: "Upload verification did not finish within the bounded polling window.",
      phase: "scan",
      retryable: true,
    });
  }

  private async withRetry<T>(
    phase: UploadPhase,
    signal: AbortSignal,
    operation: (attempt: number) => Promise<T>,
  ): Promise<T> {
    let last: UploadRejection | undefined;
    for (let attempt = 1; attempt <= this.retry.maxAttempts; attempt += 1) {
      if (signal.aborted) throw signal.reason;
      try {
        return await operation(attempt);
      } catch (error) {
        if (signal.aborted) throw signal.reason;
        last = rejectionFrom(error, phase);
        if (!last.retryable) {
          if (error instanceof UploadPortError) throw error;
          throw new UploadPortError(
            {
              code: last.code,
              message: last.message,
              phase: last.phase,
              retryable: false,
            },
            { cause: error },
          );
        }
        if (attempt < this.retry.maxAttempts) {
          await sleep(this.retry.delayMs(attempt), signal);
        }
      }
    }
    throw new UploadPortError(
      {
        code: "retry-exhausted",
        message: last?.message ?? `Upload ${phase} exhausted its retry budget.`,
        phase,
        retryable: true,
      },
      { cause: last?.cause },
    );
  }

  private bindUploadId(uploadId: string): void {
    if (uploadId.trim().length === 0) {
      throw new UploadPortError({
        code: "validation",
        message: "The upload service returned an empty upload identity.",
        phase: "initiate",
        retryable: false,
      });
    }
    if (this.uploadId !== undefined && this.uploadId !== uploadId) {
      throw new UploadPortError({
        code: "identity-conflict",
        message: "A stable workflow key resolved to a different upload object.",
        phase: "initiate",
        retryable: false,
      });
    }
    this.uploadId = uploadId;
  }

  private recordReceipt(receipt: UploadPartReceipt, plan: UploadTransferPlan): void {
    const part = plan.parts.find((candidate) => candidate.partNumber === receipt.partNumber);
    if (part === undefined || receipt.receipt.length === 0) {
      throw new UploadPortError({
        code: "identity-conflict",
        message: "A resumed part receipt does not belong to the authorized transfer plan.",
        phase: "initiate",
        retryable: false,
      });
    }
    const previous = this.receipts.get(receipt.partNumber);
    if (previous !== undefined && previous.receipt !== receipt.receipt) {
      throw new UploadPortError({
        code: "identity-conflict",
        message: "The service returned conflicting receipts for the same upload part.",
        phase: "initiate",
        retryable: false,
      });
    }
    this.receipts.set(receipt.partNumber, Object.freeze(receipt));
  }

  private phaseForState(): UploadPhase {
    switch (this.currentState.status) {
      case "checksumming":
        return "checksum";
      case "initiating":
        return "initiate";
      case "transferring":
        return "transfer";
      case "finalizing":
        return "finalize";
      case "quarantined":
        return "scan";
      default:
        return this.finalizeEntered ? "finalize" : "transfer";
    }
  }

  private transition(next: UploadState, force = false): void {
    if (!force && !legalTransitions[this.currentState.status].includes(next.status)) {
      throw new Error(`Illegal upload transition ${this.currentState.status} -> ${next.status}.`);
    }
    this.currentState = next;
    for (const listener of this.listeners) listener();
  }

  private attachExternalSignal(controller: AbortController): void {
    if (this.externalSignal === undefined) return;
    const abort = () => {
      this.cancelReason = "Upload cancelled by the caller signal.";
      controller.abort(this.externalSignal?.reason);
    };
    this.externalAbortListener = abort;
    if (this.externalSignal.aborted) abort();
    else this.externalSignal.addEventListener("abort", abort, { once: true });
  }

  private detachExternalSignal(): void {
    if (this.externalSignal !== undefined && this.externalAbortListener !== undefined) {
      this.externalSignal.removeEventListener("abort", this.externalAbortListener);
    }
    this.externalAbortListener = undefined;
  }
}

export function createUploadCoordinator(
  source: UploadSource,
  identity: UploadWorkflowIdentity,
  ports: UploadPorts,
  options?: UploadCoordinatorOptions,
): UploadCoordinator {
  return new UploadCoordinator(source, identity, ports, options);
}

export const browserChecksumPort: UploadChecksumPort = Object.freeze({
  async sha256(source: Blob, signal: AbortSignal): Promise<string> {
    const support = detectUploadBrowserSupport();
    if (!support.blobArrayBuffer || !support.sha256) {
      throw new UploadPortError({
        code: "unsupported",
        message: "This environment cannot compute the required upload SHA-256 checksum.",
        phase: "checksum",
        retryable: false,
      });
    }
    if (signal.aborted) throw signal.reason;
    const bytes = await source.arrayBuffer();
    if (signal.aborted) throw signal.reason;
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    if (signal.aborted) throw signal.reason;
    return `sha256:${Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("")}`;
  },
});

/** Real XMLHttpRequest transfer adapter for authorized direct or proxy targets. */
export const browserUploadTransfer = Object.freeze({
  async transfer(request: UploadTransferRequest): Promise<UploadPartReceipt> {
    if (request.signal.aborted) throw request.signal.reason;
    if (typeof XMLHttpRequest === "undefined") {
      throw new UploadPortError({
        code: "unsupported",
        message: "XMLHttpRequest upload progress is unavailable in this environment.",
        phase: "transfer",
        retryable: false,
      });
    }
    if (!isBrowserUploadTarget(request.part.target)) {
      throw new UploadPortError({
        code: "validation",
        message: "The upload part does not contain a browser transfer target.",
        phase: "transfer",
        retryable: false,
      });
    }
    const target = request.part.target;
    const { promise, resolve, reject } = Promise.withResolvers<UploadPartReceipt>();
    const xhr = new XMLHttpRequest();
    const abort = () => xhr.abort();
    request.signal.addEventListener("abort", abort, { once: true });
    xhr.open(target.method, target.url, true);
    xhr.withCredentials = target.withCredentials ?? false;
    for (const [name, value] of Object.entries(target.headers ?? {})) {
      xhr.setRequestHeader(name, value);
    }
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) request.reportProgress(Math.min(event.loaded, request.part.length));
    });
    xhr.addEventListener("load", () => {
      request.signal.removeEventListener("abort", abort);
      if (xhr.status >= 200 && xhr.status < 300) {
        request.reportProgress(request.part.length);
        resolve(
          Object.freeze({
            partNumber: request.part.partNumber,
            receipt: xhr.getResponseHeader("etag") ?? `http-${xhr.status}`,
          }),
        );
        return;
      }
      reject(
        new UploadPortError({
          code: "transfer",
          message: `Upload transfer failed with HTTP ${xhr.status}.`,
          phase: "transfer",
          retryable: xhr.status === 408 || xhr.status === 429 || xhr.status >= 500,
        }),
      );
    });
    xhr.addEventListener("error", () => {
      request.signal.removeEventListener("abort", abort);
      reject(
        new UploadPortError({
          code: "transfer",
          message: "Upload transfer failed before receiving an HTTP response.",
          phase: "transfer",
          retryable: true,
        }),
      );
    });
    xhr.addEventListener("abort", () => {
      request.signal.removeEventListener("abort", abort);
      reject(request.signal.reason ?? cancelledRejection("Upload transfer aborted."));
    });
    const body = target.body;
    if (body?.kind === "form") {
      const form = new FormData();
      for (const [name, value] of Object.entries(body.fields)) form.append(name, value);
      form.append(body.fileField, request.bytes, request.part.partNumber.toString());
      xhr.send(form);
    } else {
      xhr.send(request.bytes);
    }
    return promise;
  },
});

function isBrowserUploadTarget(value: unknown): value is BrowserUploadTarget {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<BrowserUploadTarget>;
  return (
    typeof candidate.url === "string" &&
    candidate.url.length > 0 &&
    (candidate.method === "POST" || candidate.method === "PUT")
  );
}

export { createHttpUploadPorts, type HttpUploadPortsConfiguration } from "./http.js";

