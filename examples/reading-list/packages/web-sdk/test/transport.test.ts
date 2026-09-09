import { describe, expect, it, vi } from "vitest";

import {
  AbortedRequestError,
  ContractMismatchError,
  GENERATED_AGAINST_CONTRACT_HASH,
  InvalidResponseError,
  RUNTIME_CONTRACT_HASH_HEADER,
  ServiceProblemError,
  createServiceClient,
} from "../src/client/index.js";

function success(body: unknown = { ok: true }): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("service transport", () => {
  it("applies relative base URL, credentials, configured/request headers, and auth", async () => {
    const fetchImplementation: typeof fetch = vi.fn(async (input, init) => {
      expect(String(input)).toBe("/api/resources");
      expect(init?.credentials).toBe("include");
      const headers = new Headers(init?.headers);
      expect(headers.get("x-configured")).toBe("configured");
      expect(headers.get("x-request")).toBe("request");
      expect(headers.get("authorization")).toBe("Bearer current");
      return success();
    });
    const client = createServiceClient({
      baseUrl: "/api",
      credentials: "include",
      fetch: fetchImplementation,
      headers: ({ method }) => ({ "x-configured": method.toLowerCase() }),
      auth: {
        mode: "bearer",
        authorize: ({ url }) => ({
          headers: {
            authorization: "Bearer current",
            "x-configured": url.pathname === "/api/resources" ? "configured" : "wrong",
          },
        }),
      },
    });

    await expect(
      client.request<{ readonly ok: boolean }>("/resources", {
        headers: { "x-request": "request" },
      }),
    ).resolves.toMatchObject({ data: { ok: true }, status: 200 });
    expect(fetchImplementation).toHaveBeenCalledOnce();
  });

  it("joins an absolute base URL without dropping its path", async () => {
    const fetchImplementation: typeof fetch = vi.fn(async (input) => {
      expect(String(input)).toBe("https://api.example.test/v2/live");
      return success();
    });
    const client = createServiceClient({
      baseUrl: "https://api.example.test/v2/",
      fetch: fetchImplementation,
    });
    await client.request("/live");
  });

  it("propagates caller abort through the actual fetch signal", async () => {
    const fetchImplementation: typeof fetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("Aborted", "AbortError")),
          { once: true },
        );
      });
    const client = createServiceClient({ baseUrl: "/api", fetch: fetchImplementation });
    const controller = new AbortController();
    const pending = client.request("/slow", { signal: controller.signal });
    controller.abort();

    await expect(pending).rejects.toMatchObject({
      name: "AbortedRequestError",
      kind: "aborted",
      reason: "caller",
      retryable: false,
    });
    await expect(pending).rejects.toBeInstanceOf(AbortedRequestError);
  });

  it("aborts an in-flight fetch when its deadline expires", async () => {
    const fetchImplementation: typeof fetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(init.signal?.reason ?? new DOMException("Aborted", "AbortError")),
          { once: true },
        );
      });
    const client = createServiceClient({ baseUrl: "/api", fetch: fetchImplementation });

    await expect(client.request("/slow", { deadlineMs: 5 })).rejects.toMatchObject({
      name: "AbortedRequestError",
      reason: "deadline",
      deadlineMs: 5,
    });
  });

  it("normalizes RFC 9457 details, request IDs, fields, and Retry-After", async () => {
    const onProblem = vi.fn(() => {
      throw new Error("observer failure");
    });
    const client = createServiceClient({
      baseUrl: "/api",
      onProblem,
      fetch: async () =>
        new Response(
          JSON.stringify({
            type: "https://example.test/problems/unavailable",
            title: "Unavailable",
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            detail: "Try later",
            request_id: "body-request",
            errors: [{ code: "INVALID", message: "Invalid value", pointer: "/name" }],
          }),
          {
            status: 503,
            headers: {
              "content-type": "application/problem+json",
              "retry-after": "2",
              "x-request-id": "header-request",
            },
          },
        ),
    });

    const pending = client.request("/resource");
    await expect(pending).rejects.toBeInstanceOf(ServiceProblemError);
    await expect(pending).rejects.toMatchObject({
      kind: "problem",
      status: 503,
      type: "https://example.test/problems/unavailable",
      code: "SERVICE_UNAVAILABLE",
      detail: "Try later",
      requestId: "header-request",
      retryable: true,
      retryAfterMs: 2_000,
      fieldViolations: [{ code: "INVALID", message: "Invalid value", pointer: "/name" }],
    });
    expect(onProblem).toHaveBeenCalledOnce();
  });

  it("keeps malformed JSON distinct from expected application problems", async () => {
    const client = createServiceClient({
      baseUrl: "/api",
      fetch: async () =>
        new Response("{", { status: 200, headers: { "content-type": "application/json" } }),
    });
    await expect(client.request("/broken")).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("reports and rejects runtime contract mismatches without exposing response bodies", async () => {
    const notifications: unknown[] = [];
    const client = createServiceClient({
      baseUrl: "/api",
      onContractMismatch: (notification) => {
        notifications.push(notification);
        throw new Error("observer failure");
      },
      fetch: async () =>
        new Response(JSON.stringify({ secret: "must-not-reach-observer" }), {
          status: 200,
          headers: {
            "content-type": "application/json",
            [RUNTIME_CONTRACT_HASH_HEADER]: `sha256:${"0".repeat(64)}`,
            "x-request-id": "contract-request",
          },
        }),
    });

    await expect(client.request("/version")).rejects.toBeInstanceOf(ContractMismatchError);
    expect(notifications).toEqual([
      {
        generatedAgainst: GENERATED_AGAINST_CONTRACT_HASH,
        runtimeContractHash: `sha256:${"0".repeat(64)}`,
        requestId: "contract-request",
      },
    ]);
  });
});
