export type CompatibilityRequestInit = RequestInit;

export class CompatibilityProblem extends Error {
  readonly status: number;
  readonly requestId: string | null;
  readonly body: unknown;

  constructor(status: number, requestId: string | null, body: unknown) {
    super(`Compatibility request failed with status ${status}`);
    this.name = "CompatibilityProblem";
    this.status = status;
    this.requestId = requestId;
    this.body = body;
  }
}

export function createCompatibilityMutator(fetchImpl: typeof fetch) {
  return async function compatibilityRequest<T>(
    url: string,
    options: CompatibilityRequestInit,
  ): Promise<T> {
    const baseUrl =
      typeof globalThis.location === "undefined"
        ? "http://localhost"
        : globalThis.location.origin;
    const response = await fetchImpl(new URL(url, baseUrl), {
      ...options,
      credentials: options.credentials ?? "same-origin",
    });
    const body = response.status === 204 ? undefined : await response.json();
    if (!response.ok) {
      throw new CompatibilityProblem(
        response.status,
        response.headers.get("x-request-id"),
        body,
      );
    }
    return body as T;
  };
}
export const compatibilityMutator = createCompatibilityMutator(globalThis.fetch);
