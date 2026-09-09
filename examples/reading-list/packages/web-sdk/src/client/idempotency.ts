import { isValidIdempotencyKey } from "./retry.js";

export const IDEMPOTENCY_KEY_HEADER = "Idempotency-Key" as const;

declare const idempotencyKeyBrand: unique symbol;
export type IdempotencyKey = string & { readonly [idempotencyKeyBrand]: true };

export function parseIdempotencyKey(value: string): IdempotencyKey {
  if (!isValidIdempotencyKey(value)) {
    throw new TypeError(
      "Idempotency key must contain between 1 and 128 visible ASCII characters.",
    );
  }
  return value as IdempotencyKey;
}

/** Generates a cryptographically strong opaque key without an insecure fallback. */
export function createIdempotencyKey(): IdempotencyKey {
  const crypto = globalThis.crypto;
  if (typeof crypto?.randomUUID !== "function") {
    throw new Error("A Web Crypto randomUUID implementation is required for idempotency keys.");
  }
  return parseIdempotencyKey(crypto.randomUUID());
}

export interface IdempotencySequence {
  readonly key: IdempotencyKey;
  readonly active: boolean;
  /** Returns a new header collection containing the stable key while the sequence is active. */
  headers(headers?: HeadersInit): Headers;
  /** Ends this business-action retry sequence and permanently prevents further reuse. */
  finish(): void;
}

/**
 * Owns exactly one controlled business-action retry sequence. A caller-provided key is accepted for
 * recovery, while generated keys are never shared across independently created sequences.
 */
export function createIdempotencySequence(
  recoveredKey?: string | IdempotencyKey,
): IdempotencySequence {
  const key = recoveredKey === undefined ? createIdempotencyKey() : parseIdempotencyKey(recoveredKey);
  let active = true;

  return Object.freeze({
    key,
    get active(): boolean {
      return active;
    },
    headers(headers?: HeadersInit): Headers {
      if (!active) {
        throw new Error("This idempotency sequence has finished and its key cannot be reused.");
      }
      const result = new Headers(headers);
      result.set(IDEMPOTENCY_KEY_HEADER, key);
      return result;
    },
    finish(): void {
      active = false;
    },
  });
}
