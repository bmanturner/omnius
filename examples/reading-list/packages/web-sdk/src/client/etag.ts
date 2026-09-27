export const ETAG_HEADER = "ETag" as const;
export const IF_MATCH_HEADER = "If-Match" as const;

export const OPTIMISTIC_CONCURRENCY_RESOLUTIONS = ["refresh", "merge", "user"] as const;
export type OptimisticConcurrencyResolution =
  (typeof OPTIMISTIC_CONCURRENCY_RESOLUTIONS)[number];

declare const strongEntityTagBrand: unique symbol;
export type StrongEntityTag = string & { readonly [strongEntityTagBrand]: true };
export type IfMatchValue = StrongEntityTag | "*";

/** Accepts one strong RFC entity-tag and rejects weak tags, lists, and wildcards. */
export function parseStrongEntityTag(value: string): StrongEntityTag {
  if (!/^"[\x21\x23-\x7e\x80-\xff]*"$/u.test(value)) {
    throw new TypeError("ETag must be one strong quoted entity tag.");
  }
  return value as StrongEntityTag;
}

/** Encodes the backend's canonical positive revision tag (`"v<revision>"`). */
export function createVersionEntityTag(version: number): StrongEntityTag {
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new RangeError("Entity-tag version must be a positive safe integer.");
  }
  return parseStrongEntityTag(`"v${String(version)}"`);
}

export function readStrongEntityTag(headers: Headers): StrongEntityTag | undefined {
  const value = headers.get(ETAG_HEADER);
  return value === null ? undefined : parseStrongEntityTag(value);
}

export function withIfMatch(headers: HeadersInit | undefined, value: IfMatchValue): Headers {
  const result = new Headers(headers);
  result.set(IF_MATCH_HEADER, value === "*" ? value : parseStrongEntityTag(value));
  return result;
}

export function isOptimisticConcurrencyStatus(status: number): boolean {
  return status === 409 || status === 412 || status === 428;
}
