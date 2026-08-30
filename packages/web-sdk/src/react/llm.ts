import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
  type QueryKey,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";
import { useMemo } from "react";

import {
  AI_OPERATION_IDS,
  createLlmClient,
  type LlmClient,
  type LlmJob,
  type LlmJobSubmission,
  type LlmRequest,
  type LlmRequestOptions,
  type LlmResponse,
  type LlmRouteList,
  type LlmStreamOptions,
  type ValidatedLlmStreamItem,
} from "../llm/index.js";
import type { ServiceResponse } from "../client/index.js";
import { useServiceClient } from "./core.js";

export const llmQueryKeys = Object.freeze({
  routes(tenantId: string | null) {
    return ["omnius", { tenantId }, "llm", AI_OPERATION_IDS.routesList] as const;
  },
  response(tenantId: string | null, requestKey: string) {
    return [
      "omnius",
      { tenantId },
      "llm",
      AI_OPERATION_IDS.responseStream,
      requestKey,
    ] as const;
  },
  job(tenantId: string | null, jobId: string) {
    return ["omnius", { tenantId }, "llm", AI_OPERATION_IDS.jobGet, jobId] as const;
  },
  jobResult(tenantId: string | null, jobId: string) {
    return ["omnius", { tenantId }, "llm", AI_OPERATION_IDS.jobResult, jobId] as const;
  },
});

export interface LlmStreamQueryState {
  readonly eventCount: number;
  readonly latest: ValidatedLlmStreamItem;
  readonly terminal: Extract<ValidatedLlmStreamItem, { readonly kind: "terminal" }> | null;
}

export interface LlmStreamMutationInput {
  readonly request: LlmRequest;
  /** Stable caller key used only for TanStack reconciliation, normally the idempotency key. */
  readonly requestKey: string;
  readonly options?: LlmStreamOptions;
}

/** Streams canonical events into one deterministic TanStack Query resource. */
export async function streamLlmIntoQueryCache(
  queryClient: QueryClient,
  llm: LlmClient,
  queryKey: QueryKey,
  request: LlmRequest,
  options: LlmStreamOptions = {},
): Promise<LlmStreamQueryState> {
  let state: LlmStreamQueryState | undefined;
  for await (const item of llm.streamResponse(request, options)) {
    state = Object.freeze({
      eventCount: (state?.eventCount ?? 0) + 1,
      latest: item,
      terminal: item.kind === "terminal" ? item : null,
    });
    queryClient.setQueryData(queryKey, state);
  }
  if (state === undefined || state.terminal === null) {
    throw new Error("The validated LLM stream did not produce a terminal query state.");
  }
  return state;
}

/** Returns one memoized framework-neutral LLM client for the current provider. */
export function useLlmClient(): LlmClient {
  const client = useServiceClient();
  return useMemo(() => createLlmClient(client), [client]);
}

/** Loads product-approved model routes into the canonical tenant-scoped key. */
export function useLlmRoutes(
  tenantId: string | null,
  options: LlmRequestOptions = {},
): UseQueryResult<LlmRouteList, Error> {
  const llm = useLlmClient();
  return useQuery({
    queryKey: llmQueryKeys.routes(tenantId),
    queryFn: async () => (await llm.listRoutes(options)).data,
  });
}

/** Creates canonical synchronous responses as an explicit non-retrying mutation. */
export function useCreateLlmResponse(): UseMutationResult<
  ServiceResponse<LlmResponse>,
  Error,
  { readonly request: LlmRequest; readonly options?: LlmRequestOptions }
> {
  const llm = useLlmClient();
  return useMutation({
    mutationFn: ({ request, options }) => llm.createResponse(request, options),
    retry: false,
  });
}

/** Submits canonical requests for durable execution and invalidates the returned job key. */
export function useSubmitLlmJob(
  tenantId: string | null,
): UseMutationResult<
  ServiceResponse<LlmJobSubmission>,
  Error,
  { readonly request: LlmRequest; readonly options?: LlmRequestOptions }
> {
  const llm = useLlmClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ request, options }) => llm.submitJob(request, options),
    onSuccess: (response) =>
      queryClient.invalidateQueries({
        queryKey: llmQueryKeys.job(tenantId, response.data.job_id),
      }),
    retry: false,
  });
}

/** Polls one durable job in its canonical tenant-scoped key. */
export function useLlmJob(
  tenantId: string | null,
  jobId: string,
  options: LlmRequestOptions = {},
  refetchIntervalMs: number | false = 2_000,
): UseQueryResult<LlmJob, Error> {
  const llm = useLlmClient();
  return useQuery({
    queryKey: llmQueryKeys.job(tenantId, jobId),
    queryFn: async () => (await llm.getJob(jobId, options)).data,
    refetchInterval: refetchIntervalMs,
  });
}

/** Cancels one durable job and reconciles its canonical job key. */
export function useCancelLlmJob(
  tenantId: string | null,
): UseMutationResult<
  ServiceResponse<void>,
  Error,
  { readonly jobId: string; readonly options?: LlmRequestOptions }
> {
  const llm = useLlmClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ jobId, options }) => llm.cancelJob(jobId, options),
    onSuccess: (_response, variables) =>
      queryClient.invalidateQueries({
        queryKey: llmQueryKeys.job(tenantId, variables.jobId),
      }),
    retry: false,
  });
}

/** Loads an unchanged canonical durable result after job completion. */
export function useLlmJobResult(
  tenantId: string | null,
  jobId: string,
  options: LlmRequestOptions = {},
  enabled = true,
): UseQueryResult<LlmResponse, Error> {
  const llm = useLlmClient();
  return useQuery({
    queryKey: llmQueryKeys.jobResult(tenantId, jobId),
    queryFn: async () => (await llm.getJobResult(jobId, options)).data,
    enabled,
  });
}

/** Starts canonical SSE and reconciles each validated event into one TanStack Query key. */
export function useStreamLlmResponse(
  tenantId: string | null,
): UseMutationResult<LlmStreamQueryState, Error, LlmStreamMutationInput> {
  const llm = useLlmClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ request, requestKey, options }) =>
      streamLlmIntoQueryCache(
        queryClient,
        llm,
        llmQueryKeys.response(tenantId, requestKey),
        request,
        options,
      ),
    retry: false,
  });
}
