import { describe, expect, it } from "vitest";

import {
  createIdempotencySequence,
  createVersionEntityTag,
  isOptimisticConcurrencyStatus,
  parseCursorPagination,
  parseOpaqueCursor,
  parseStrongEntityTag,
  scopeQueryKey,
  serializeCursorPagination,
  shouldRetryRequest,
  withIfMatch,
} from "../src/client/index.js";

describe("HTTP retry policy", () => {
  const retryable = { retryable: true } as const;

  it("allows retryable idempotent methods within the attempt bound", () => {
    expect(
      shouldRetryRequest({
        method: "GET",
        attempt: 1,
        error: retryable,
        policy: { maxAttempts: 2 },
      }),
    ).toBe(true);
    expect(
      shouldRetryRequest({
        method: "DELETE",
        attempt: 2,
        error: retryable,
        policy: { maxAttempts: 2 },
      }),
    ).toBe(false);
  });

  it("requires both a valid caller key and explicit policy for non-idempotent methods", () => {
    const base = {
      method: "POST",
      attempt: 1,
      error: retryable,
      idempotencyKey: "workflow-key",
    } as const;
    expect(shouldRetryRequest({ ...base, policy: { maxAttempts: 2 } })).toBe(false);
    expect(
      shouldRetryRequest({
        ...base,
        idempotencyKey: "invalid key",
        policy: { maxAttempts: 2, retryNonIdempotentWithKey: true },
      }),
    ).toBe(false);
    expect(
      shouldRetryRequest({
        ...base,
        policy: { maxAttempts: 2, retryNonIdempotentWithKey: true },
      }),
    ).toBe(true);
    expect(
      shouldRetryRequest({
        ...base,
        method: "PATCH",
        policy: { maxAttempts: 2, retryNonIdempotentWithKey: true },
      }),
    ).toBe(true);
  });
});

describe("cursor pagination and query scope", () => {
  it("round-trips opaque cursor pagination without interpreting the cursor", () => {
    const cursor = parseOpaqueCursor("opaque+/=cursor");
    const encoded = serializeCursorPagination({ cursor, limit: 25 });
    expect(encoded.toString()).toBe("cursor=opaque%2B%2F%3Dcursor&limit=25");
    expect(parseCursorPagination(encoded)).toEqual({ cursor, limit: 25 });
  });

  it("keeps tenant, principal, and permission scope in cache keys", () => {
    const generated = ["listReferenceRecords", { cursor: "opaque", limit: 25 }] as const;
    const scoped = scopeQueryKey(generated, {
      tenantId: "tenant-1",
      principalId: "principal-1",
      permissionScope: "permissions-v2",
    });
    expect(scoped).toEqual([
      "omnius",
      {
        tenantId: "tenant-1",
        principalId: "principal-1",
        permissionScope: "permissions-v2",
      },
      ...generated,
    ]);
    expect(Object.isFrozen(scoped)).toBe(true);
  });
});

describe("idempotency workflow boundaries", () => {
  it("reuses one strong key only while its controlled sequence is active", () => {
    const first = createIdempotencySequence();
    const second = createIdempotencySequence();
    expect(first.key).toMatch(/^[0-9a-f-]{36}$/u);
    expect(first.key).not.toBe(second.key);
    expect(first.headers().get("idempotency-key")).toBe(first.key);
    expect(first.headers({ "x-action": "retry" }).get("idempotency-key")).toBe(first.key);
    first.finish();
    expect(first.active).toBe(false);
    expect(() => first.headers()).toThrow(/finished/u);
  });

  it("accepts an existing key for explicit workflow recovery", () => {
    const recovered = createIdempotencySequence("persisted-action-key");
    expect(recovered.headers().get("idempotency-key")).toBe("persisted-action-key");
  });
});

describe("optimistic concurrency helpers", () => {
  it("creates strong version ETags and applies If-Match without losing headers", () => {
    const tag = createVersionEntityTag(42);
    expect(tag).toBe('"v42"');
    expect(parseStrongEntityTag(tag)).toBe(tag);
    expect(withIfMatch({ "x-request": "one" }, tag)).toEqual(
      new Headers({ "if-match": '"v42"', "x-request": "one" }),
    );
  });

  it("rejects weak validators and identifies typed resolution statuses", () => {
    expect(() => parseStrongEntityTag('W/"v42"')).toThrow(TypeError);
    expect(isOptimisticConcurrencyStatus(412)).toBe(true);
    expect(isOptimisticConcurrencyStatus(428)).toBe(true);
    expect(isOptimisticConcurrencyStatus(422)).toBe(false);
  });
});
