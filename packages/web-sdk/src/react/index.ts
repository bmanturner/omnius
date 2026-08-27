import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { QueryClientConfig } from "@tanstack/react-query";
import {
  createContext,
  createElement,
  useContext,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";

import {
  createServiceClient,
  ServiceClientError,
  ServiceProblemError,
} from "../client/index.js";
import type {
  ContractMismatchNotification,
  DefinedServiceClientConfiguration,
  ServiceClient,
} from "../client/index.js";
import {
  getGetCurrentPrincipalQueryKey,
  getGetLivenessQueryKey,
  getGetReadinessQueryKey,
  getGetReferenceRecordQueryKey,
  getGetRuntimeMetadataQueryKey,
  getGetStartupQueryKey,
  getGetVersionQueryKey,
  getListReferenceRecordsQueryKey,
} from "../internal/generated/http/react-query.js";

export * as serviceQueries from "../internal/generated/http/react-query.js";

export const SERVICE_QUERY_STALE_TIME_MS = 30_000;
export const SERVICE_QUERY_GC_TIME_MS = 5 * 60_000;
export const SERVICE_QUERY_MAX_RETRIES = 2;

const nonRetryableProblemStatuses: Readonly<Record<number, true>> = {
  400: true,
  401: true,
  403: true,
  404: true,
  409: true,
  412: true,
  413: true,
  415: true,
  422: true,
  428: true,
};

/**
 * Stable generated key factories exposed by operation identity. Consumers scope these with
 * `scopeQueryKey` from the framework-neutral client entry rather than writing cache strings.
 */
export const serviceQueryKeys = Object.freeze({
  getCurrentPrincipal: getGetCurrentPrincipalQueryKey,
  getLiveness: getGetLivenessQueryKey,
  getReadiness: getGetReadinessQueryKey,
  getReferenceRecord: getGetReferenceRecordQueryKey,
  getRuntimeMetadata: getGetRuntimeMetadataQueryKey,
  getStartup: getGetStartupQueryKey,
  getVersion: getGetVersionQueryKey,
  listReferenceRecords: getListReferenceRecordsQueryKey,
});

/** Queries retry only normalized transient failures, never caller or client errors. */
export function shouldRetryServiceQuery(failureCount: number, error: unknown): boolean {
  if (failureCount >= SERVICE_QUERY_MAX_RETRIES || !(error instanceof ServiceClientError)) {
    return false;
  }
  if (
    error instanceof ServiceProblemError &&
    nonRetryableProblemStatuses[error.status] === true
  ) {
    return false;
  }
  return error.retryable;
}

/**
 * Creates an isolated query cache with service-safe browser defaults.
 *
 * Queries are fresh for 30 seconds and retained for five minutes. They refetch when a stale
 * observer regains focus or reconnects. At most two retries are attempted for normalized,
 * retryable service failures. Mutations never retry automatically.
 */
export function createServiceQueryClient(
  configuration: QueryClientConfig = {},
): QueryClient {
  const queries = configuration.defaultOptions?.queries;
  const mutations = configuration.defaultOptions?.mutations;
  return new QueryClient({
    ...configuration,
    defaultOptions: {
      ...configuration.defaultOptions,
      queries: {
        staleTime: SERVICE_QUERY_STALE_TIME_MS,
        gcTime: SERVICE_QUERY_GC_TIME_MS,
        retry: shouldRetryServiceQuery,
        refetchOnWindowFocus: true,
        refetchOnReconnect: true,
        ...queries,
      },
      mutations: {
        retry: false,
        ...mutations,
      },
    },
  });
}

export interface ServiceErrorPresentation {
  readonly title: string;
  readonly detail: string;
  readonly requestId?: string;
}

/** Converts the normalized transport error union into a safe, display-ready problem. */
export function presentServiceError(error: unknown): ServiceErrorPresentation {
  if (error instanceof ServiceProblemError) {
    return {
      title: error.title,
      detail: error.detail ?? "The service could not complete this request.",
      ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
    };
  }
  if (error instanceof ServiceClientError) {
    return {
      title: "Service request failed",
      detail: error.message,
      ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
    };
  }
  return {
    title: "Unexpected application error",
    detail: "The application could not complete this request.",
  };
}

interface WebSdkContextValue {
  readonly client: ServiceClient;
  readonly contractMismatch: Readonly<ContractMismatchNotification> | null;
}

const WebSdkContext = createContext<WebSdkContextValue | null>(null);

export interface WebSdkProviderProps {
  readonly configuration: Readonly<DefinedServiceClientConfiguration>;
  readonly queryClient?: QueryClient;
  readonly children?: ReactNode;
}

/**
 * Owns one service client and one TanStack Query cache per provider instance. Generated request
 * options remain explicitly bound to the client; no process-global transport state is used.
 */
export function WebSdkProvider({
  children,
  configuration,
  queryClient,
}: WebSdkProviderProps): ReactNode {
  const [contractMismatch, setContractMismatch] =
    useState<Readonly<ContractMismatchNotification> | null>(null);
  const client = useMemo(
    () =>
      createServiceClient({
        ...configuration,
        onContractMismatch: (mismatch) => {
          setContractMismatch(mismatch);
          configuration.onContractMismatch?.(mismatch);
        },
      }),
    [configuration],
  );
  const ownedQueryClient = useMemo(
    () => queryClient ?? createServiceQueryClient(),
    [client, queryClient],
  );
  const context = useMemo(
    () => ({ client, contractMismatch }),
    [client, contractMismatch],
  );

  return createElement(
    WebSdkContext.Provider,
    { value: context },
    createElement(QueryClientProvider, { client: ownedQueryClient }, children),
  );
}

function useWebSdkContext(): WebSdkContextValue {
  const context = useContext(WebSdkContext);
  if (context === null) {
    throw new Error("Web SDK hooks must be used within WebSdkProvider.");
  }
  return context;
}

export function useServiceClient(): ServiceClient {
  return useWebSdkContext().client;
}

export function useClientConfiguration(): Readonly<DefinedServiceClientConfiguration> {
  return useServiceClient().configuration;
}

export function useContractMismatch(): Readonly<ContractMismatchNotification> | null {
  return useWebSdkContext().contractMismatch;
}
