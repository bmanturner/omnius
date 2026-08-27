import { hashKey } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import {
  getGetReferenceRecordQueryKey,
  getListReferenceRecordsQueryKey,
} from "../generated/client";
import {
  CompatibilityProblem,
  createCompatibilityMutator,
} from "./mutator";

describe("Orval compatibility boundary", () => {
  it("preserves credentials, cancellation, problem body, and request ID", async () => {
    const controller = new AbortController();
    const fetchImpl: typeof fetch = async (_input, init) => {
      expect(init?.credentials).toBe("same-origin");
      expect(init?.signal).toBe(controller.signal);
      return new Response(
        JSON.stringify({
          type: "https://example.invalid/problems/conflict",
          title: "Conflict",
          status: 409,
          code: "REFERENCE_CONFLICT",
        }),
        {
          status: 409,
          headers: {
            "content-type": "application/problem+json",
            "x-request-id": "req-mutator",
          },
        },
      );
    };
    const request = createCompatibilityMutator(fetchImpl);

    const response = request("/reference-records", {
      method: "POST",
      signal: controller.signal,
    });
    await expect(response).rejects.toBeInstanceOf(CompatibilityProblem);
    await expect(response).rejects.toMatchObject({
      status: 409,
      requestId: "req-mutator",
      body: {
        type: "https://example.invalid/problems/conflict",
        title: "Conflict",
        status: 409,
        code: "REFERENCE_CONFLICT",
      },
    });
  });

  it("propagates abort cancellation to the injected fetch", async () => {
    const controller = new AbortController();
    const { promise, reject } = Promise.withResolvers<Response>();
    const fetchImpl: typeof fetch = (_input, init) => {
      init?.signal?.addEventListener(
        "abort",
        () => reject(new DOMException("Aborted", "AbortError")),
        { once: true },
      );
      return promise;
    };
    const request = createCompatibilityMutator(fetchImpl);
    const pending = request("/reference-records", {
      method: "GET",
      signal: controller.signal,
    });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });

  it("produces stable path and normalized query-key hashes", () => {
    const first = getListReferenceRecordsQueryKey({
      limit: 25,
      cursor: "cursor-fixture",
    });
    const reordered = getListReferenceRecordsQueryKey({
      cursor: "cursor-fixture",
      limit: 25,
    });
    expect(hashKey(first)).toBe(hashKey(reordered));
    expect(getGetReferenceRecordQueryKey("record-1")).toEqual([
      "/reference-records/record-1",
    ]);
  });
});
