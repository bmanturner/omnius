import { describe, expect, it } from "vitest";

import type { ServiceClient, ServiceRequestOptions } from "../src/client/transport.js";
import { createHttpUploadPorts, createUploadWorkflowIdentity, type UploadTransferRequest } from "../src/uploads/index.js";

const SHA256 = `sha256:${"1".repeat(64)}`;

describe("HTTP upload ports", () => {
  it("binds tenant and retry identity while preserving authenticated proxy progress", async () => {
    const calls: Array<{ path: string; options: ServiceRequestOptions }> = [];
    const transfers: UploadTransferRequest[] = [];
    const client: ServiceClient = {
      configuration: Object.freeze({
        baseUrl: "/api",
        credentials: "include",
        headers: { "X-Application": "web" },
        auth: { mode: "bearer" as const, authorize: async () => ({ headers: { Authorization: "Bearer token" } }) },
      }),
      request: async <T>(path: string, options: ServiceRequestOptions = {}) => {
        calls.push({ path, options });
        const data = path === "/uploads"
          ? {
              decision: "started",
              uploadId: "upload-1",
              transfer: {
                mode: "proxied",
                parts: [{
                  partNumber: 1,
                  offset: 0,
                  length: 4,
                  target: { url: "/uploads/upload-1/content", method: "PUT", headers: { "X-Omnius-Tenant-Id": "tenant-1" }, body: { kind: "raw" } },
                }],
              },
            }
          : { state: "quarantined", revision: 2 };
        return { data: data as T, status: 200, headers: new Headers() };
      },
      requestOptions: (options = {}) => options,
    };
    const ports = createHttpUploadPorts({
      client,
      tenantId: "tenant-1",
      transfer: { transfer: async (request) => { transfers.push(request); request.reportProgress(request.part.length); return { partNumber: 1, receipt: "http-204" }; } },
    });
    const identity = createUploadWorkflowIdentity("workflow-1", "retry-1");
    const signal = new AbortController().signal;
    const initiated = await ports.initiate({ identity, fileName: "safe.png", mediaType: "image/png", byteLength: 4, sha256: SHA256 }, signal);
    expect(initiated.decision).toBe("started");
    if (initiated.decision !== "started") throw new Error("expected started upload");
    const progress: number[] = [];
    await ports.transfer({ identity, uploadId: initiated.uploadId, mode: initiated.transfer.mode, part: initiated.transfer.parts[0]!, bytes: new Blob(["data"]), sha256: SHA256, signal, reportProgress: (value) => progress.push(value) });
    const status = await ports.finalize({ identity, uploadId: initiated.uploadId, sha256: SHA256, parts: [{ partNumber: 1, receipt: "http-204" }], signal });

    expect((calls[0]?.options.headers as Headers).get("X-Omnius-Tenant-Id")).toBe("tenant-1");
    expect((calls[0]?.options.headers as Headers).get("Idempotency-Key")).toBe("retry-1");
    expect(transfers[0]?.part.target).toMatchObject({
      url: "/api/uploads/upload-1/content",
      withCredentials: true,
      headers: { authorization: "Bearer token", "x-application": "web", "x-omnius-tenant-id": "tenant-1" },
    });
    expect(progress).toEqual([4]);
    expect(status).toEqual({ state: "quarantined", revision: 2 });
  });

  it("uses identity-verifying POST routes for status and abandonment", async () => {
    const calls: string[] = [];
    const client: ServiceClient = {
      configuration: Object.freeze({ baseUrl: "https://api.example.test" }),
      request: async <T>(path: string) => { calls.push(path); return { data: { state: "deleted", revision: 8 } as T, status: 200, headers: new Headers() }; },
      requestOptions: (options = {}) => options,
    };
    const ports = createHttpUploadPorts({ client, tenantId: "tenant-1", transfer: { transfer: async () => ({ partNumber: 1, receipt: "unused" }) } });
    const identity = createUploadWorkflowIdentity("workflow-1", "retry-1");
    const signal = new AbortController().signal;
    await expect(ports.getStatus({ identity, uploadId: "upload-1", signal })).resolves.toEqual({ state: "deleted", revision: 8 });
    await expect(ports.abandon({ identity, uploadId: "upload-1", signal })).resolves.toBeUndefined();
    expect(calls).toEqual(["/uploads/upload-1/status", "/uploads/upload-1/abandon"]);
  });
});
