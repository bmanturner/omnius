import { describe, expect, it } from "vitest";

import {
  createUploadCoordinator,
  createUploadWorkflowIdentity,
  UploadPortError,
} from "../src/uploads/index.js";
import type {
  UploadChecksumPort,
  UploadFinalizeRequest,
  UploadInitiationRequest,
  UploadPorts,
  UploadState,
  UploadStatusRequest,
  UploadTransferRequest,
} from "../src/uploads/index.js";

const SHA256 = `sha256:${"1".repeat(64)}`;
const checksum: UploadChecksumPort = {
  sha256: async () => SHA256,
};

function source(value = "abcdefgh"): { data: Blob; fileName: string; mediaType: string } {
  return {
    data: new Blob([value], { type: "application/octet-stream" }),
    fileName: "fixture.bin",
    mediaType: "application/octet-stream",
  };
}

function identity() {
  return createUploadWorkflowIdentity("workflow-123", "idempotency-123");
}

function coordinatorOptions() {
  return {
    checksum,
    retry: { maxAttempts: 3, delayMs: () => 0 },
    scanPollIntervalMs: 0,
    maxScanPolls: 3,
  } as const;
}

describe("upload coordinator", () => {
  it("retries multipart transfer with one stable identity, progress, checksum, finalize, and quarantine", async () => {
    const initiations: UploadInitiationRequest[] = [];
    const transfers: UploadTransferRequest[] = [];
    const finalizations: UploadFinalizeRequest[] = [];
    const statuses: UploadStatusRequest[] = [];
    const snapshots: UploadState[] = [];
    let firstPartAttempts = 0;
    let statusPolls = 0;
    const ports: UploadPorts = {
      initiate: async (request) => {
        initiations.push(request);
        return {
          decision: "started",
          uploadId: "upload-1",
          transfer: {
            mode: "direct",
            parts: [
              { partNumber: 1, offset: 0, length: 4, target: { signed: "one" } },
              { partNumber: 2, offset: 4, length: 4, target: { signed: "two" } },
            ],
          },
        };
      },
      transfer: async (request) => {
        transfers.push(request);
        if (request.part.partNumber === 1) {
          firstPartAttempts += 1;
          if (firstPartAttempts === 1) {
            request.reportProgress(2);
            throw new UploadPortError({
              code: "transfer",
              message: "temporary direct-upload failure",
              phase: "transfer",
              retryable: true,
            });
          }
        }
        request.reportProgress(request.part.length);
        return { partNumber: request.part.partNumber, receipt: `etag-${request.part.partNumber}` };
      },
      finalize: async (request) => {
        finalizations.push(request);
        return { state: "quarantined", revision: 1 };
      },
      getStatus: async (request) => {
        statuses.push(request);
        statusPolls += 1;
        return statusPolls === 1
          ? { state: "quarantined", revision: 2 }
          : { state: "available", revision: 3 };
      },
      abandon: async () => undefined,
    };
    const coordinator = createUploadCoordinator(source(), identity(), ports, coordinatorOptions());
    const unsubscribe = coordinator.subscribe(() => snapshots.push(coordinator.state));

    const result = await coordinator.start();
    unsubscribe();

    expect(result).toEqual({ status: "available", available: true, uploadId: "upload-1" });
    expect(initiations).toHaveLength(1);
    expect(initiations[0]?.sha256).toBe(SHA256);
    expect(transfers).toHaveLength(3);
    expect(transfers.every((request) => request.identity === coordinator.identity)).toBe(true);
    expect(finalizations).toHaveLength(1);
    expect(finalizations[0]?.parts).toEqual([
      { partNumber: 1, receipt: "etag-1" },
      { partNumber: 2, receipt: "etag-2" },
    ]);
    expect(statuses).toHaveLength(2);
    expect(
      snapshots
        .filter((snapshot) => snapshot.status === "transferring")
        .map((snapshot) => snapshot.progress.bytesTransferred),
    ).toEqual([2, 4, 8]);
    expect(snapshots.filter((snapshot) => snapshot.status !== "available").every(
      (snapshot) => !snapshot.available,
    )).toBe(true);
  });

  it("cancels an in-flight part and resumes the same upload without a duplicate finalize", async () => {
    const entered = Promise.withResolvers<void>();
    const initiationIdentities: string[] = [];
    let transferAttempts = 0;
    let finalizations = 0;
    const ports: UploadPorts = {
      initiate: async (request) => {
        initiationIdentities.push(request.identity.idempotencyKey);
        return {
          decision: "started",
          uploadId: "upload-resume",
          transfer: {
            mode: "proxied",
            parts: [{ partNumber: 1, offset: 0, length: 8, target: "/authorized-proxy" }],
          },
        };
      },
      transfer: async (request) => {
        transferAttempts += 1;
        if (transferAttempts === 1) {
          entered.resolve();
          const aborted = Promise.withResolvers<never>();
          request.signal.addEventListener("abort", () => aborted.reject(request.signal.reason), {
            once: true,
          });
          return aborted.promise;
        }
        request.reportProgress(8);
        return { partNumber: 1, receipt: "proxy-receipt" };
      },
      finalize: async () => {
        finalizations += 1;
        return { state: "available" };
      },
      getStatus: async () => ({ state: "available" }),
      abandon: async () => undefined,
    };
    const coordinator = createUploadCoordinator(source(), identity(), ports, coordinatorOptions());
    const firstRun = coordinator.start();
    await entered.promise;
    coordinator.cancel("user paused upload");

    expect(await firstRun).toMatchObject({
      status: "cancelled",
      reason: "user paused upload",
      resumable: true,
      available: false,
    });
    expect(await coordinator.resume()).toEqual({
      status: "available",
      available: true,
      uploadId: "upload-resume",
    });
    expect(initiationIdentities).toEqual(["idempotency-123", "idempotency-123"]);
    expect(transferAttempts).toBe(2);
    expect(finalizations).toBe(1);
  });

  it("resumes multipart plans from durable part receipts", async () => {
    const transferredParts: number[] = [];
    const ports: UploadPorts = {
      initiate: async () => ({
        decision: "started",
        uploadId: "upload-parts",
        completedParts: [{ partNumber: 1, receipt: "durable-etag-1" }],
        transfer: {
          mode: "direct",
          parts: [
            { partNumber: 1, offset: 0, length: 4, target: "expired-url-is-not-used" },
            { partNumber: 2, offset: 4, length: 4, target: "fresh-url" },
          ],
        },
      }),
      transfer: async (request) => {
        transferredParts.push(request.part.partNumber);
        request.reportProgress(request.part.length);
        return { partNumber: request.part.partNumber, receipt: "durable-etag-2" };
      },
      finalize: async (request) => {
        expect(request.parts).toEqual([
          { partNumber: 1, receipt: "durable-etag-1" },
          { partNumber: 2, receipt: "durable-etag-2" },
        ]);
        return { state: "available" };
      },
      getStatus: async () => ({ state: "available" }),
      abandon: async () => undefined,
    };

    expect(
      await createUploadCoordinator(source(), identity(), ports, coordinatorOptions()).start(),
    ).toMatchObject({ status: "available", available: true });
    expect(transferredParts).toEqual([2]);
  });

  it("keeps rejected initiation unavailable and never transfers or finalizes", async () => {
    let transfers = 0;
    let finalizations = 0;
    const rejection = {
      code: "authorization" as const,
      message: "not authorized",
      phase: "initiate" as const,
      retryable: false,
    };
    const ports: UploadPorts = {
      initiate: async () => ({ decision: "rejected", rejection }),
      transfer: async () => {
        transfers += 1;
        return { partNumber: 1, receipt: "impossible" };
      },
      finalize: async () => {
        finalizations += 1;
        return { state: "available" };
      },
      getStatus: async () => ({ state: "available" }),
      abandon: async () => undefined,
    };

    expect(
      await createUploadCoordinator(source(), identity(), ports, coordinatorOptions()).start(),
    ).toEqual({ status: "rejected", available: false, rejection });
    expect(transfers).toBe(0);
    expect(finalizations).toBe(0);
  });

  it("rejects an unrelated object returned for the same workflow key on resume", async () => {
    const entered = Promise.withResolvers<void>();
    let initiations = 0;
    const ports: UploadPorts = {
      initiate: async () => {
        initiations += 1;
        return {
          decision: "started",
          uploadId: initiations === 1 ? "upload-original" : "upload-unrelated",
          transfer: {
            mode: "proxied",
            parts: [{ partNumber: 1, offset: 0, length: 8, target: "/proxy" }],
          },
        };
      },
      transfer: async (request) => {
        entered.resolve();
        const aborted = Promise.withResolvers<never>();
        request.signal.addEventListener("abort", () => aborted.reject(request.signal.reason), {
          once: true,
        });
        return aborted.promise;
      },
      finalize: async () => ({ state: "available" }),
      getStatus: async () => ({ state: "available" }),
      abandon: async () => undefined,
    };
    const coordinator = createUploadCoordinator(source(), identity(), ports, coordinatorOptions());
    const first = coordinator.start();
    await entered.promise;
    coordinator.cancel();
    await first;

    expect(await coordinator.resume()).toMatchObject({
      status: "failed",
      available: false,
      rejection: { code: "identity-conflict", retryable: false },
    });
  });

  it("abandons an authorized unfinished object during clean disposal", async () => {
    const entered = Promise.withResolvers<void>();
    const abandoned: string[] = [];
    const ports: UploadPorts = {
      initiate: async () => ({
        decision: "started",
        uploadId: "upload-abandoned",
        transfer: {
          mode: "proxied",
          parts: [{ partNumber: 1, offset: 0, length: 8, target: "/proxy" }],
        },
      }),
      transfer: async (request) => {
        entered.resolve();
        const aborted = Promise.withResolvers<never>();
        request.signal.addEventListener("abort", () => aborted.reject(request.signal.reason), {
          once: true,
        });
        return aborted.promise;
      },
      finalize: async () => ({ state: "available" }),
      getStatus: async () => ({ state: "quarantined" }),
      abandon: async (request) => {
        abandoned.push(request.uploadId);
      },
    };
    const coordinator = createUploadCoordinator(source(), identity(), ports, coordinatorOptions());
    void coordinator.start();
    await entered.promise;
    await coordinator.dispose();

    expect(abandoned).toEqual(["upload-abandoned"]);
    expect(coordinator.state).toEqual({
      status: "disposed",
      available: false,
      uploadId: "upload-abandoned",
      abandoned: true,
    });
  });

  it("stops retryable transfer failures at the configured safe bound", async () => {
    let transferAttempts = 0;
    let finalizations = 0;
    const ports: UploadPorts = {
      initiate: async () => ({
        decision: "started",
        uploadId: "upload-retry-bound",
        transfer: {
          mode: "proxied",
          parts: [{ partNumber: 1, offset: 0, length: 8, target: "/proxy" }],
        },
      }),
      transfer: async () => {
        transferAttempts += 1;
        throw new UploadPortError({
          code: "transfer",
          message: "temporary proxy failure",
          phase: "transfer",
          retryable: true,
        });
      },
      finalize: async () => {
        finalizations += 1;
        return { state: "available" };
      },
      getStatus: async () => ({ state: "available" }),
      abandon: async () => undefined,
    };
    const coordinator = createUploadCoordinator(source(), identity(), ports, coordinatorOptions());

    expect(await coordinator.start()).toMatchObject({
      status: "failed",
      available: false,
      rejection: { code: "retry-exhausted", phase: "transfer", retryable: true },
    });
    expect(transferAttempts).toBe(3);
    expect(finalizations).toBe(0);
  });
});
