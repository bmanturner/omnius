import { executeBoundServiceRequest, type ServiceClientError } from "./transport.js";

/** Error surface consumed by generated TanStack Query options. */
export type ErrorType<_ExpectedProblem> = ServiceClientError;

interface OrvalRequestOptions extends RequestInit {
  readonly params?: Readonly<Record<string, unknown>>;
  readonly data?: unknown;
}

function appendQueryParameters(path: string, parameters: Readonly<Record<string, unknown>>): string {
  const separator = path.includes("?") ? "&" : "?";
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(parameters)) {
    if (value === undefined) {
      continue;
    }
    const values = Array.isArray(value) ? value : [value];
    for (const item of values) {
      if (
        item !== null &&
        typeof item !== "string" &&
        typeof item !== "number" &&
        typeof item !== "boolean"
      ) {
        throw new TypeError(`Unsupported generated query parameter: ${name}`);
      }
      search.append(name, item === null ? "null" : String(item));
    }
  }
  const encoded = search.toString();
  return encoded.length === 0 ? path : `${path}${separator}${encoded}`;
}

/** Native-fetch mutator used only by derived Orval output. Client state arrives in request options. */
export function serviceMutator<T>(
  url: string,
  options: OrvalRequestOptions,
): Promise<T> {
  const { data, params, ...requestOptions } = options;
  const path = params === undefined ? url : appendQueryParameters(url, params);
  const request: RequestInit = {
    ...requestOptions,
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  };
  return executeBoundServiceRequest<unknown>(path, request) as Promise<T>;
}
