import { hashKey, QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import { createServiceClient } from "../src/client/index.js";
import { serviceQueries, serviceQueryKeys } from "../src/react/index.js";
import { serviceHttp } from "../src/client/index.js";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("generated HTTP surface", () => {
  it("calls a generated operation through an explicit service client", async () => {
    const client = createServiceClient({
      baseUrl: "https://api.example.test/v1",
      fetch: async (input) => {
        expect(String(input)).toBe("https://api.example.test/v1/live");
        return jsonResponse({ status: "live" });
      },
    });

    await expect(serviceHttp.getLiveness(client.requestOptions())).resolves.toMatchObject({
      data: { status: "live" },
      status: 200,
    });
  });

  it("exports stable generated key factories through semantic operation names", () => {
    const first = serviceQueryKeys.listReferenceRecords({
      limit: 25,
      cursor: "opaque-cursor",
    });
    const reordered = serviceQueryKeys.listReferenceRecords({
      cursor: "opaque-cursor",
      limit: 25,
    });
    expect(hashKey(first)).toBe(hashKey(reordered));
    expect(hashKey(serviceQueryKeys.getReferenceRecord("record-1"))).not.toBe(
      hashKey(serviceQueryKeys.getReferenceRecord("record-2")),
    );
  });

  it("propagates TanStack Query cancellation into the generated fetch request", async () => {
    const fetchImplementation: typeof fetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("Aborted", "AbortError")),
          { once: true },
        );
      });
    const client = createServiceClient({ baseUrl: "/api", fetch: fetchImplementation });
    const query = serviceQueries.getGetLivenessQueryOptions({
      request: client.requestOptions(),
    });
    if (typeof query.queryFn !== "function") {
      throw new Error("Generated query options did not include a query function.");
    }
    const controller = new AbortController();
    const queryClient = new QueryClient();
    const context = {
      client: queryClient,
      queryKey: query.queryKey,
      signal: controller.signal,
      meta: undefined,
    } as Parameters<typeof query.queryFn>[0];
    const pending = query.queryFn(context);
    controller.abort();

    await expect(pending).rejects.toMatchObject({
      name: "AbortedRequestError",
      reason: "caller",
    });
  });
});
