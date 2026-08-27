import type { ComponentType, ReactNode } from "react";

import type { DefinedServiceClientConfiguration } from "../client/index.js";
import {
  getGetCurrentPrincipalQueryKey,
  getGetLivenessQueryKey,
  getGetReadinessQueryKey,
  getGetReferenceRecordQueryKey,
  getGetStartupQueryKey,
  getGetVersionQueryKey,
  getListReferenceRecordsQueryKey,
} from "../internal/generated/http/react-query.js";

export * as serviceQueries from "../internal/generated/http/react-query.js";

/**
 * Stable generated key factories exposed by operation identity. Consumers scope these with
 * `scopeQueryKey` from the framework-neutral client entry rather than writing cache strings.
 */
export const serviceQueryKeys = Object.freeze({
  getCurrentPrincipal: getGetCurrentPrincipalQueryKey,
  getLiveness: getGetLivenessQueryKey,
  getReadiness: getGetReadinessQueryKey,
  getReferenceRecord: getGetReferenceRecordQueryKey,
  getStartup: getGetStartupQueryKey,
  getVersion: getGetVersionQueryKey,
  listReferenceRecords: getListReferenceRecordsQueryKey,
});

export interface WebSdkProviderProps {
  readonly configuration: Readonly<DefinedServiceClientConfiguration>;
  readonly children?: ReactNode;
}

/**
 * React-specific registration boundary. The core never imports this module, and React remains
 * an optional peer for consumers that do not use this entry point.
 */
export interface WebSdkReactAdapter {
  readonly Provider: ComponentType<WebSdkProviderProps>;
  readonly useClientConfiguration: () => Readonly<DefinedServiceClientConfiguration>;
}

/** Captures an immutable adapter registration without importing React at runtime. */
export function defineWebSdkReactAdapter(
  adapter: WebSdkReactAdapter,
): Readonly<WebSdkReactAdapter> {
  return Object.freeze({
    Provider: adapter.Provider,
    useClientConfiguration: adapter.useClientConfiguration,
  });
}
