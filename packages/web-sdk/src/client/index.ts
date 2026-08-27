import type { AuthAdapter } from "../auth/index.js";

export {
  CONTRACT_AGGREGATE_SHA256,
  CONTRACT_COMPATIBILITY_WINDOW,
  GENERATED_AGAINST_CONTRACT_HASH,
} from "../internal/generated/contract-metadata.js";
export type { ContractCompatibilityWindow } from "../internal/generated/contract-metadata.js";

export interface ClientRequestContext {
  readonly url: URL;
  readonly method: string;
  readonly signal?: AbortSignal;
}

export type ClientHeaders =
  | HeadersInit
  | ((context: ClientRequestContext) => HeadersInit | Promise<HeadersInit>);

export interface ClientProblemNotification {
  readonly status: number;
  readonly type: string;
  readonly title: string;
  readonly detail?: string;
  readonly requestId?: string;
}

export interface ContractMismatchNotification {
  readonly generatedAgainst: string;
  readonly runtimeContractHash: string;
  readonly runtimeMinimumSdkVersion?: string;
  readonly runtimeMaximumSdkVersion?: string | null;
}

/**
 * Transport-independent inputs consumed by the service-client factory.
 * Defining configuration performs URL validation but never starts I/O.
 */
export interface ServiceClientConfiguration {
  readonly baseUrl: string | URL;
  readonly credentials?: RequestCredentials;
  readonly headers?: ClientHeaders;
  readonly fetch?: typeof globalThis.fetch;
  readonly auth?: AuthAdapter;
  readonly onProblem?: (problem: ClientProblemNotification) => void;
  readonly onContractMismatch?: (mismatch: ContractMismatchNotification) => void;
}

export type DefinedServiceClientConfiguration = Omit<
  ServiceClientConfiguration,
  "baseUrl"
> & {
  readonly baseUrl: string;
};

/** Validates and canonicalizes an HTTP(S) absolute or same-origin root-relative base URL. */
export function normalizeServiceBaseUrl(baseUrl: string | URL): string {
  const value = baseUrl instanceof URL ? baseUrl.href : baseUrl;
  if (value.length === 0 || value.trim() !== value) {
    throw new TypeError("Service base URL must be a non-empty value without surrounding whitespace.");
  }

  if (value.startsWith("/")) {
    if (value.startsWith("//")) {
      throw new TypeError("Protocol-relative service base URLs are not allowed.");
    }
    const parsedRelative = new URL(value, "https://omnius.invalid");
    if (parsedRelative.search.length > 0 || parsedRelative.hash.length > 0) {
      throw new TypeError("Service base URL must not include a query string or fragment.");
    }
    return parsedRelative.pathname.length > 1 && parsedRelative.pathname.endsWith("/")
      ? parsedRelative.pathname.slice(0, -1)
      : parsedRelative.pathname;
  }

  let parsedAbsolute: URL;
  try {
    parsedAbsolute = new URL(value);
  } catch (error: unknown) {
    throw new TypeError("Service base URL must be HTTP(S) absolute or root-relative.", {
      cause: error,
    });
  }
  if (parsedAbsolute.protocol !== "http:" && parsedAbsolute.protocol !== "https:") {
    throw new TypeError("Service base URL must use HTTP or HTTPS.");
  }
  if (parsedAbsolute.username.length > 0 || parsedAbsolute.password.length > 0) {
    throw new TypeError("Service base URL must not contain credentials.");
  }
  if (parsedAbsolute.search.length > 0 || parsedAbsolute.hash.length > 0) {
    throw new TypeError("Service base URL must not include a query string or fragment.");
  }

  const href = parsedAbsolute.href;
  return parsedAbsolute.pathname === "/" ? href : href.replace(/\/$/u, "");
}

/** Returns a top-level immutable configuration snapshot suitable for client construction. */
export function defineServiceClientConfiguration(
  configuration: ServiceClientConfiguration,
): Readonly<DefinedServiceClientConfiguration> {
  return Object.freeze({
    ...configuration,
    baseUrl: normalizeServiceBaseUrl(configuration.baseUrl),
  });
}
