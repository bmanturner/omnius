export const IDEMPOTENT_HTTP_METHODS = [
  "GET",
  "HEAD",
  "OPTIONS",
  "TRACE",
  "PUT",
  "DELETE",
] as const;

export type IdempotentHttpMethod = (typeof IDEMPOTENT_HTTP_METHODS)[number];

export interface RetryClassification {
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
}

export interface RetryPolicy {
  /** Total attempts, including the first request. */
  readonly maxAttempts: number;
  /** Initial exponential delay. Defaults to 100 ms. */
  readonly baseDelayMs?: number;
  /** Maximum exponential delay. Defaults to 2 seconds. */
  readonly maxDelayMs?: number;
  /** Explicit opt-in for POST/PATCH retries protected by an idempotency key. */
  readonly retryNonIdempotentWithKey?: boolean;
}

export interface RetryDecisionInput {
  readonly method: string;
  /** One-based number of the attempt that just failed. */
  readonly attempt: number;
  readonly error: RetryClassification;
  readonly policy: RetryPolicy;
  readonly idempotencyKey?: string;
}

export function isValidIdempotencyKey(value: string): boolean {
  return value.length > 0 && value.length <= 128 && /^[\x21-\x7e]+$/u.test(value);
}

export function isIdempotentHttpMethod(method: string): method is IdempotentHttpMethod {
  const normalized = method.toUpperCase();
  return (
    normalized === "GET" ||
    normalized === "HEAD" ||
    normalized === "OPTIONS" ||
    normalized === "TRACE" ||
    normalized === "PUT" ||
    normalized === "DELETE"
  );
}

export function validateRetryPolicy(policy: RetryPolicy): void {
  if (!Number.isSafeInteger(policy.maxAttempts) || policy.maxAttempts < 1) {
    throw new RangeError("Retry maxAttempts must be a positive safe integer.");
  }
  for (const [name, value] of [
    ["baseDelayMs", policy.baseDelayMs],
    ["maxDelayMs", policy.maxDelayMs],
  ] as const) {
    if (value !== undefined && (!Number.isFinite(value) || value < 0)) {
      throw new RangeError(`Retry ${name} must be a finite non-negative number.`);
    }
  }
  if (
    policy.baseDelayMs !== undefined &&
    policy.maxDelayMs !== undefined &&
    policy.baseDelayMs > policy.maxDelayMs
  ) {
    throw new RangeError("Retry baseDelayMs must not exceed maxDelayMs.");
  }
}

/** Applies method, error, attempt, and idempotency gates without performing I/O. */
export function shouldRetryRequest(input: RetryDecisionInput): boolean {
  validateRetryPolicy(input.policy);
  if (!input.error.retryable || input.attempt >= input.policy.maxAttempts) {
    return false;
  }
  if (isIdempotentHttpMethod(input.method)) {
    return true;
  }
  const method = input.method.toUpperCase();
  return (
    (method === "POST" || method === "PATCH") &&
    input.policy.retryNonIdempotentWithKey === true &&
    input.idempotencyKey !== undefined &&
    isValidIdempotencyKey(input.idempotencyKey)
  );
}

export function retryDelayMs(
  attempt: number,
  policy: RetryPolicy,
  retryAfterMs?: number,
): number {
  validateRetryPolicy(policy);
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw new RangeError("Retry attempt must be a positive safe integer.");
  }
  if (retryAfterMs !== undefined && Number.isFinite(retryAfterMs) && retryAfterMs >= 0) {
    return retryAfterMs;
  }
  const base = policy.baseDelayMs ?? 100;
  const maximum = policy.maxDelayMs ?? 2_000;
  return Math.min(maximum, base * 2 ** Math.min(attempt - 1, 30));
}
